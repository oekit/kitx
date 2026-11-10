package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// newTestKeyPair 生成测试用密钥对。
func newTestKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return kp
}

// decodeSegment 解 JWT 的某一段（raw url base64）。
func decodeSegment(t *testing.T, token string, idx int) map[string]any {
	t.Helper()
	parts := splitToken(token)
	if len(parts) != 3 {
		t.Fatalf("token parts = %d, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[idx])
	if err != nil {
		t.Fatalf("decode segment %d: %v", idx, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal segment %d: %v", idx, err)
	}
	return m
}

// splitToken 按 '.' 切 JWT 三段。
func splitToken(token string) []string { return strings.Split(token, ".") }

func TestSignParseRoundTrip(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp,
		WithIssuer("self"),
		WithSubject("user-1"),
		WithJTI("jti-1"),
		WithTTL(time.Hour),
		WithClaim("un", "alice"),
		WithClaim("source", "dao"),
		WithClaim("mfaVerified", true),
	)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	got, err := Parse(token, kp.Public)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Issuer != "self" {
		t.Fatalf("Issuer = %q, want self", got.Issuer)
	}
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
	if got.ID != "jti-1" {
		t.Fatalf("ID = %q, want jti-1", got.ID)
	}
	if got.Extra["un"] != "alice" {
		t.Fatalf("Extra[un] = %v, want alice", got.Extra["un"])
	}
	if got.Extra["source"] != "dao" {
		t.Fatalf("Extra[source] = %v, want dao", got.Extra["source"])
	}
	if got.Extra["mfaVerified"] != true {
		t.Fatalf("Extra[mfaVerified] = %v, want true", got.Extra["mfaVerified"])
	}
}

// 硬契约：header 只有 alg，不带 typ（与 Nimbus/既有消费方互通）。
func TestHeaderHasNoTyp(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	hdr := decodeSegment(t, token, 0)
	if hdr["alg"] != "RS256" {
		t.Fatalf("header[alg] = %v, want RS256", hdr["alg"])
	}
	if _, ok := hdr["typ"]; ok {
		t.Fatalf("header must not contain typ, got %v", hdr)
	}
	if len(hdr) != 1 {
		t.Fatalf("header keys = %v, want only alg", hdr)
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	kp := newTestKeyPair(t)
	other := newTestKeyPair(t)
	token, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := Parse(token, other.Public); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() with wrong key must wrap ErrInvalidToken, got %v", err)
	}
}

func TestParseRejectsExpired(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp, WithSubject("u"), WithTTL(-time.Minute))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := Parse(token, kp.Public); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() with expired token must wrap ErrInvalidToken, got %v", err)
	}
	// 容忍时钟偏移后同一令牌必须通过。
	if _, err := Parse(token, kp.Public, WithLeeway(2*time.Minute)); err != nil {
		t.Fatalf("Parse() with leeway = %v, want nil", err)
	}
}

// #70：Parse 保留底层错误链——过期令牌与伪造令牌靠 gojwt 的 sentinel 可区分，
// 业务侧「过期→走刷新、签名坏→踢下线」的分流才能落地。
//
// 缺陷成因：外层用 fmt.Errorf("%w: %v") 把 gojwt 的 ErrTokenExpired/
// ErrTokenSignatureInvalid 拍平成纯文本，errors.Is 对底层 sentinel 全部失效。
func TestParseErrorChainPreserved(t *testing.T) {
	kp := newTestKeyPair(t)
	expired, err := Sign(kp, WithSubject("u"), WithTTL(-time.Minute))
	if err != nil {
		t.Fatalf("Sign() expired error = %v", err)
	}
	_, err = Parse(expired, kp.Public)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("外层哨兵仍可判：errors.Is(ErrInvalidToken) = false, err = %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenExpired) {
		t.Fatalf("过期令牌必须能 Is 到 gojwt.ErrTokenExpired, err = %v", err)
	}

	other := newTestKeyPair(t)
	forged, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() forged error = %v", err)
	}
	_, err = Parse(forged, other.Public)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("外层哨兵仍可判：errors.Is(ErrInvalidToken) = false, err = %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenSignatureInvalid) {
		t.Fatalf("错密钥令牌必须能 Is 到 gojwt.ErrTokenSignatureInvalid, err = %v", err)
	}
}

// PEM 往返：GenerateKeyPair 的输出必须能被 ParsePrivateKey/ParsePublicKey 读回。
func TestPEMRoundTrip(t *testing.T) {
	kp := newTestKeyPair(t)
	privPEM, pubPEM, err := MarshalKeyPairPEM(kp)
	if err != nil {
		t.Fatalf("MarshalKeyPairPEM() error = %v", err)
	}
	priv, err := ParsePrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Fatalf("priv bits = %d, want 2048", priv.N.BitLen())
	}
	pub, err := ParsePublicKey([]byte(pubPEM))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Fatal("public key does not match private key")
	}
	_ = kp
}

// 兼容形态：既有消费方用「结构体 claims + omitempty」签发的令牌必须能被 Parse 读回
// （un/source/mfaVerified=false 缺省时不在 payload 里，Parse 不得因此报错）。
func TestParseStructClaimsShape(t *testing.T) {
	kp := newTestKeyPair(t)
	privPEM, _, err := MarshalKeyPairPEM(kp)
	if err != nil {
		t.Fatalf("MarshalKeyPairPEM() error = %v", err)
	}
	priv, err := ParsePrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	tok := gojwtToken(priv, "user-9", "dao")
	tokenStr, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	got, err := Parse(tokenStr, kp.Public)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Subject != "user-9" {
		t.Fatalf("Subject = %q, want user-9", got.Subject)
	}
	if got.Extra["source"] != "dao" {
		t.Fatalf("Extra[source] = %v, want dao", got.Extra["source"])
	}
	if _, ok := got.Extra["un"]; ok {
		t.Fatalf("Extra must not contain absent claim un, got %v", got.Extra)
	}
}

// gojwtToken 用 golang-jwt 原生 RegisteredClaims（struct 形态）构造令牌，
// 模拟「结构体 claims + omitempty」签发方的产物（如 kuboard-go 既有实现）。
func gojwtToken(priv *rsa.PrivateKey, sub, source string) *gojwt.Token {
	claims := struct {
		gojwt.RegisteredClaims
		Source string `json:"source,omitempty"`
	}{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:   "self",
			Subject:  sub,
			ID:       "jti-x",
			IssuedAt: gojwt.NewNumericDate(time.Now()),
		},
		Source: source,
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	delete(tok.Header, "typ")
	return tok
}

// rawClaimsToken 用 gojwt.MapClaims 直接构造令牌（#71 后 WithClaim 不能注入
// 注册声明，测试需要构造带 aud / 类型异常注册声明的令牌时改走这条路，
// 模拟「第三方/异常形态签发方」的产物）。header 保持硬契约形态（只含 alg）。
func rawClaimsToken(t *testing.T, kp *KeyPair, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header = map[string]any{"alg": "RS256"}
	s, err := tok.SignedString(kp.Private)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return s
}

// #64：WithIssuedAt 显式 iat——iat 取注入时刻、exp = iat + ttl 同源，两次签发完全确定。
func TestSignWithIssuedAt(t *testing.T) {
	kp := newTestKeyPair(t)
	// 取未来时刻（2100-01-01 UTC），保证 exp 仍在有效期、可走 Parse 往返。
	fixed := time.Unix(4102444800, 0).UTC()
	token, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithIssuedAt(fixed))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	payload := decodeSegment(t, token, 1)
	if got := payload["iat"]; got != float64(fixed.Unix()) {
		t.Fatalf("payload[iat] = %v, want %d", got, fixed.Unix())
	}
	if got := payload["exp"]; got != float64(fixed.Add(time.Hour).Unix()) {
		t.Fatalf("payload[exp] = %v, want %d", got, fixed.Add(time.Hour).Unix())
	}
	// 确定性：同参两次签发 iat 完全一致（缺省时钟只能断言 iat≈now 区间）。
	again, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithIssuedAt(fixed))
	if err != nil {
		t.Fatalf("Sign() again error = %v", err)
	}
	if got := decodeSegment(t, again, 1)["iat"]; got != float64(fixed.Unix()) {
		t.Fatalf("second payload[iat] = %v, want %d（注入时钟下必须确定）", got, fixed.Unix())
	}
	// 解析侧读回同一签发时刻。
	got, err := Parse(token, kp.Public)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.IssuedAt == nil || got.IssuedAt.Unix() != fixed.Unix() {
		t.Fatalf("IssuedAt = %v, want %d", got.IssuedAt, fixed.Unix())
	}
}

// #64：WithNow 注入假时钟——连续签发走同一钟源逐次推进，exp 与 iat 同源。
func TestSignWithNow(t *testing.T) {
	kp := newTestKeyPair(t)
	base := time.Now().Add(time.Hour).Truncate(time.Second) // 未来基准，保证 exp 未过期
	seq := 0
	clock := func() time.Time {
		seq++
		return base.Add(time.Duration(seq) * time.Second)
	}
	first, err := Sign(kp, WithSubject("u"), WithTTL(time.Minute), WithNow(clock))
	if err != nil {
		t.Fatalf("Sign() first error = %v", err)
	}
	second, err := Sign(kp, WithSubject("u"), WithTTL(time.Minute), WithNow(clock))
	if err != nil {
		t.Fatalf("Sign() second error = %v", err)
	}
	p1, p2 := decodeSegment(t, first, 1), decodeSegment(t, second, 1)
	if p1["iat"] != float64(base.Add(time.Second).Unix()) {
		t.Fatalf("first iat = %v, want %d", p1["iat"], base.Add(time.Second).Unix())
	}
	if p2["iat"] != float64(base.Add(2*time.Second).Unix()) {
		t.Fatalf("second iat = %v, want %d", p2["iat"], base.Add(2*time.Second).Unix())
	}
	if p1["exp"] != float64(base.Add(time.Second).Add(time.Minute).Unix()) {
		t.Fatalf("first exp = %v, want iat+ttl", p1["exp"])
	}
	if _, err := Parse(first, kp.Public); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

// #64：WithNow(nil) 必须当场 panic——静默回落真实时钟会让 iat 无声漂移。
func TestWithNowNilPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("WithNow(nil) must panic")
		}
	}()
	kp := newTestKeyPair(t)
	_, _ = Sign(kp, WithNow(nil))
}

// #64：缺省行为不变——无时钟选项时 iat 取真实当前时刻（区间断言），且缺省 ttl 仍为 24h。
func TestSignDefaultClockAndTTL(t *testing.T) {
	kp := newTestKeyPair(t)
	before := time.Now().Unix()
	token, err := Sign(kp, WithSubject("u"))
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	payload := decodeSegment(t, token, 1)
	iat := int64(payload["iat"].(float64))
	if iat < before || iat > after {
		t.Fatalf("iat = %d, want within [%d, %d]", iat, before, after)
	}
	if exp := int64(payload["exp"].(float64)); exp != iat+24*3600 {
		t.Fatalf("exp = %d, want iat+24h = %d", exp, iat+24*3600)
	}
}

// #65：WithTTL(0) 直接 panic——显式 0 与「未设置」不可区分，静默产出无 exp 令牌。
func TestWithTTLZeroPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("WithTTL(0) must panic")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "WithTTL(0)") {
			t.Fatalf("panic message = %v, want mention of WithTTL(0)", r)
		}
	}()
	kp := newTestKeyPair(t)
	_, _ = Sign(kp, WithSubject("u"), WithTTL(0))
}

// #65：无过期令牌必须显式 WithNoExpiry——payload 不含 exp 且可正常解析；与 WithTTL last-wins。
func TestWithNoExpiry(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp, WithSubject("u"), WithNoExpiry())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	payload := decodeSegment(t, token, 1)
	if _, ok := payload["exp"]; ok {
		t.Fatalf("payload must not contain exp, got %v", payload)
	}
	if _, err := Parse(token, kp.Public); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	// last-wins：WithNoExpiry 之后再 WithTTL 恢复写 exp。
	token2, err := Sign(kp, WithSubject("u"), WithNoExpiry(), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() token2 error = %v", err)
	}
	payload2 := decodeSegment(t, token2, 1)
	if _, ok := payload2["exp"]; !ok {
		t.Fatalf("WithTTL after WithNoExpiry must re-enable exp (last-wins), got %v", payload2)
	}
}

// #66：WithAudience 受众校验——命中任一通过；令牌无 aud 且配置了期望受众 ⇒ fail-closed 拒绝。
func TestParseWithAudience(t *testing.T) {
	kp := newTestKeyPair(t)
	// aud 是注册声明，#71 后不可经 WithClaim 注入，用 rawClaimsToken 构造
	// 带 aud 的令牌（模拟第三方签发方产物）。
	single := rawClaimsToken(t, kp, gojwt.MapClaims{"aud": "svc-a"})
	multi := rawClaimsToken(t, kp, gojwt.MapClaims{"aud": []any{"svc-a", "svc-b"}})
	none, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() none error = %v", err)
	}

	// 命中任一即通过（string / 数组两种 aud 形态）。
	if _, err := Parse(single, kp.Public, WithAudience("svc-a")); err != nil {
		t.Fatalf("Parse() matching audience = %v, want nil", err)
	}
	if _, err := Parse(single, kp.Public, WithAudience("svc-b", "svc-a")); err != nil {
		t.Fatalf("Parse() any-of audience = %v, want nil", err)
	}
	if _, err := Parse(multi, kp.Public, WithAudience("svc-b")); err != nil {
		t.Fatalf("Parse() array audience = %v, want nil", err)
	}
	// aud 仍收进 Claims.Audience。
	got, err := Parse(single, kp.Public, WithAudience("svc-a"))
	if err != nil {
		t.Fatalf("Parse() collect error = %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "svc-a" {
		t.Fatalf("Audience = %v, want [svc-a]", got.Audience)
	}
	// 不匹配 ⇒ 拒绝，错误并入 ErrInvalidToken 包装链。
	if _, err := Parse(single, kp.Public, WithAudience("svc-b")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() mismatched audience must wrap ErrInvalidToken, got %v", err)
	}
	// fail-closed：令牌无 aud 且配置了期望受众 ⇒ 拒绝。
	if _, err := Parse(none, kp.Public, WithAudience("svc-a")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() absent aud with expected audience must wrap ErrInvalidToken, got %v", err)
	}
	// 向后兼容：不配置 WithAudience 时不校验 aud，无 aud 令牌照常通过。
	if _, err := Parse(none, kp.Public); err != nil {
		t.Fatalf("Parse() without audience check = %v, want nil", err)
	}
}

// #117：签发→解析 aud 闭环——WithAudienceClaims 签出带 aud 的令牌，与解析侧
// WithAudience（#66 fail-closed）对接；单受众写 string 形态、多受众写 []string
// 形态（与 claimsFromMap 对称）。修复前此闭环在本包走不通：WithClaim("aud")
// 被 #71 拒、无签发出口，WithAudience 的目标场景只能出自外部签名者（本用例
// 即 jwt_test 一直缺失的「签发→解析」aud 闭环证据）。
func TestSignWithAudienceClaimsRoundTrip(t *testing.T) {
	kp := newTestKeyPair(t)
	single, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithAudienceClaims("svc-a"))
	if err != nil {
		t.Fatalf("Sign() single error = %v", err)
	}
	if got := decodeSegment(t, single, 1)["aud"]; got != "svc-a" {
		t.Fatalf("单受众必须写 string 形态, payload[aud] = %v", got)
	}
	// 签发→解析闭环：WithAudience 命中通过、不匹配拒绝（#66 fail-closed 不变）。
	if _, err := Parse(single, kp.Public, WithAudience("svc-a")); err != nil {
		t.Fatalf("Parse(WithAudience(svc-a)) = %v, want nil（闭环）", err)
	}
	if _, err := Parse(single, kp.Public, WithAudience("svc-b")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse(WithAudience(svc-b)) 不匹配受众必须拒绝, got %v", err)
	}
	got, err := Parse(single, kp.Public, WithAudience("svc-a"))
	if err != nil {
		t.Fatalf("Parse() collect error = %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "svc-a" {
		t.Fatalf("Audience = %v, want [svc-a]", got.Audience)
	}

	multi, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithAudienceClaims("svc-a", "svc-b"))
	if err != nil {
		t.Fatalf("Sign() multi error = %v", err)
	}
	arr, ok := decodeSegment(t, multi, 1)["aud"].([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("多受众必须写 []string 形态, payload[aud] = %v", decodeSegment(t, multi, 1)["aud"])
	}
	if _, err := Parse(multi, kp.Public, WithAudience("svc-b")); err != nil {
		t.Fatalf("Parse(WithAudience(svc-b)) 数组形态 any-of = %v, want nil", err)
	}
	gotMulti, err := Parse(multi, kp.Public, WithAudience("svc-a"))
	if err != nil {
		t.Fatalf("Parse() multi collect error = %v", err)
	}
	if len(gotMulti.Audience) != 2 {
		t.Fatalf("Audience = %v, want [svc-a svc-b]", gotMulti.Audience)
	}

	// 零参与不设置同效（显式回退默认值）：令牌不带 aud，向后兼容面不变。
	none, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithAudienceClaims())
	if err != nil {
		t.Fatalf("Sign() zero-arg error = %v", err)
	}
	if _, ok := decodeSegment(t, none, 1)["aud"]; ok {
		t.Fatalf("零参与必须不写 aud, payload = %v", decodeSegment(t, none, 1))
	}
	if _, err := Parse(none, kp.Public); err != nil {
		t.Fatalf("Parse() zero-arg token = %v, want nil", err)
	}

	// HS256 形态共享 signPayload，同一签发语义。
	signer := newTestSigner(t)
	hsToken, err := signer.Sign(WithSubject("u"), WithTTL(time.Hour), WithAudienceClaims("svc-a", "svc-b"))
	if err != nil {
		t.Fatalf("SymmetricSigner.Sign() error = %v", err)
	}
	if _, err := ParseSymmetric(hsToken, testHS256Secret(t), WithAudience("svc-b")); err != nil {
		t.Fatalf("ParseSymmetric(WithAudience(svc-b)) = %v, want nil（HS256 同语义）", err)
	}
}

// #117：空串受众 fail-fast——空受众是配置零值透传的最常见形态，签出的令牌在
// WithAudience（#66）fail-closed 校验下永不匹配（WithTTL(0) panic（#65）同款
// 纪律：非法入参启动即暴露好过静默产出废令牌）。
func TestWithAudienceClaimsEmptyStringPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("WithAudienceClaims(\"\") must panic")
		}
	}()
	kp := newTestKeyPair(t)
	_, _ = Sign(kp, WithSubject("u"), WithAudienceClaims("svc-a", ""))
}

// #117：#71 保留声明报错指引补上 aud 的签发出口——此前指引只列
// WithIssuer/WithSubject/WithJTI/WithNotBefore，aud 只进不出。
func TestSignReservedClaimErrorPointsToAudienceExit(t *testing.T) {
	kp := newTestKeyPair(t)
	_, err := Sign(kp, WithClaim("aud", "injected"))
	if err == nil {
		t.Fatal("WithClaim(aud) 必须被 #71 拒绝")
	}
	if !strings.Contains(err.Error(), "WithAudienceClaims") {
		t.Fatalf("error = %v, 必须指引到 aud 的签发出口 WithAudienceClaims（#117）", err)
	}
}

// #67：类型异常的注册声明 fail-closed——iss/sub/jti 存在但非字符串（如 Java 侧
// Long 序列化出的数值 sub、数组 iss）时 Parse 拒绝并带声明名与实际类型，不再
// 静默归零成空 Subject 放行（RFC 7519 §4.1.1/§4.1.2 要求 iss/sub MUST be a String）。
func TestParseRejectsClaimTypeAnomaly(t *testing.T) {
	kp := newTestKeyPair(t)
	// 注册声明不可经 WithClaim 注入（#71），用 rawClaimsToken 构造
	// 「存在但类型异常」的违规令牌（模拟第三方/Java 侧 Long 序列化产物）。
	numSub := rawClaimsToken(t, kp, gojwt.MapClaims{"sub": 12345})
	arrIss := rawClaimsToken(t, kp, gojwt.MapClaims{"iss": []any{"a", "b"}})
	boolJTI := rawClaimsToken(t, kp, gojwt.MapClaims{"jti": true})
	cases := []struct {
		name  string
		token string
		want  string // 期望错误文案片段：声明名 + 实际类型
	}{
		{"numeric sub", numSub, "声明 sub 类型异常: float64"},
		{"array iss", arrIss, "声明 iss 类型异常: []interface {}"},
		{"boolean jti", boolJTI, "声明 jti 类型异常: bool"},
	}
	for _, tc := range cases {
		_, err := Parse(tc.token, kp.Public)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("[%s] Parse() must wrap ErrInvalidToken, got %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("[%s] error = %v, want contains %q", tc.name, err, tc.want)
		}
	}
}

// #67：只有「存在但类型异常」才 fail-closed——缺失 iss/sub/jti 的令牌维持零值
// 不报错，缺 sub 的令牌按消费方自身的校验责任走。
func TestParseMissingClaimsStayZero(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp, WithTTL(time.Hour)) // 不带 iss/sub/jti
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	got, err := Parse(token, kp.Public)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil（缺失声明不报错）", err)
	}
	if got.Issuer != "" || got.Subject != "" || got.ID != "" {
		t.Fatalf("missing claims must stay zero values, got iss=%q sub=%q jti=%q", got.Issuer, got.Subject, got.ID)
	}
}

// #71：WithClaim 注入注册声明必须被 Sign 拒绝——Sign 先写注册声明、最后平铺
// claims 且无条件覆盖，WithClaim("exp", ...) 顶掉过期时间、WithClaim("iss",
// externalInput) 篡改签发者；claim key 来自配置/请求拼接时即令牌声明注入面。
func TestSignRejectsReservedClaimInjection(t *testing.T) {
	kp := newTestKeyPair(t)
	for _, key := range []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti"} {
		token, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithClaim(key, "injected"))
		if err == nil {
			t.Fatalf("Sign() with WithClaim(%q) must be rejected, got token %s", key, token)
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Sign() with WithClaim(%q) must wrap ErrInvalidToken, got %v", key, err)
		}
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("error %v must name the reserved claim %q", err, key)
		}
	}
	// 业务自定义声明不受影响，照常平铺进 payload。
	token, err := Sign(kp, WithSubject("u"), WithClaim("un", "alice"), WithClaim("source", "dao"))
	if err != nil {
		t.Fatalf("Sign() with custom claims = %v, want nil", err)
	}
	payload := decodeSegment(t, token, 1)
	if payload["un"] != "alice" || payload["source"] != "dao" {
		t.Fatalf("custom claims must be flattened into payload, got %v", payload)
	}
}
