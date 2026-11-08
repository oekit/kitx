package jwt

import (
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// testHS256Secret 32 字节测试密钥（RFC 7518 §3.2 下限恰好通过）。
func testHS256Secret(t *testing.T) []byte {
	t.Helper()
	return []byte("0123456789abcdef0123456789abcdef")
}

func newTestSigner(t *testing.T) *SymmetricSigner {
	t.Helper()
	s, err := NewSymmetric(testHS256Secret(t))
	if err != nil {
		t.Fatalf("NewSymmetric() error = %v", err)
	}
	return s
}

// TestNewSymmetricRejectsWeakSecret 锁定 #86 设计点 2：secret 缺失/弱密钥构造期
// fail-fast（RFC 7518 §3.2 下限 32 字节），对齐全仓「配置错误宁可启动即暴露」哲学。
func TestNewSymmetricRejectsWeakSecret(t *testing.T) {
	for name, secret := range map[string][]byte{
		"nil":     nil,
		"empty":   {},
		"占位符6字节":  []byte("secret"),
		"31字节零密钥": make([]byte, 31),
	} {
		if _, err := NewSymmetric(secret); err == nil {
			t.Fatalf("NewSymmetric [%s] 必须报错（弱密钥构造期暴露，#86）", name)
		}
	}
	if _, err := NewSymmetric(make([]byte, 32)); err != nil {
		t.Fatalf("NewSymmetric(32B) error = %v, want nil（恰好下限应通过）", err)
	}
}

// TestSymmetricSignParseRoundTrip 与 RS256 形态对齐（#86）：同一套 SignOption、
// 同一 Claims 收集（注册声明收进 RegisteredClaims、其余进 Extra）、header 只含
// alg 不带 typ。
func TestSymmetricSignParseRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	token, err := s.Sign(
		WithIssuer("self"),
		WithSubject("user-1"),
		WithJTI("jti-1"),
		WithTTL(time.Hour),
		WithClaim("un", "alice"),
		WithClaim("mfaVerified", true),
	)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	hdr := decodeSegment(t, token, 0)
	if hdr["alg"] != "HS256" {
		t.Fatalf("header[alg] = %v, want HS256", hdr["alg"])
	}
	if _, ok := hdr["typ"]; ok {
		t.Fatalf("header must not contain typ, got %v", hdr)
	}
	if len(hdr) != 1 {
		t.Fatalf("header keys = %v, want only alg", hdr)
	}
	got, err := ParseSymmetric(token, testHS256Secret(t))
	if err != nil {
		t.Fatalf("ParseSymmetric() error = %v", err)
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
	if got.Extra["mfaVerified"] != true {
		t.Fatalf("Extra[mfaVerified] = %v, want true", got.Extra["mfaVerified"])
	}
	if got.IssuedAt == nil || got.ExpiresAt == nil || got.ExpiresAt.Unix()-got.IssuedAt.Unix() != 3600 {
		t.Fatalf("exp-iat 应为 ttl=1h, got iat=%v exp=%v", got.IssuedAt, got.ExpiresAt)
	}
}

// TestParseSymmetricRejectsWrongSecret 错密钥拒绝——HMAC 校验 + #70 错误链语义在
// HS256 同效（可 Is 到 gojwt.ErrTokenSignatureInvalid）。
func TestParseSymmetricRejectsWrongSecret(t *testing.T) {
	s := newTestSigner(t)
	token, err := s.Sign(WithSubject("u"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	other, err := NewSymmetric([]byte("another-secret-0123456789abcdefg")) // 32 字节
	if err != nil {
		t.Fatalf("NewSymmetric() error = %v", err)
	}
	_, err = ParseSymmetric(token, other.secret)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseSymmetric() 错密钥必须 wrap ErrInvalidToken, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenSignatureInvalid) {
		t.Fatalf("错密钥必须可 Is 到 gojwt.ErrTokenSignatureInvalid, got %v", err)
	}
}

// TestParseSymmetricExpiredAndLeeway 过期令牌拒绝 + leeway 容忍（#70/#66 校验
// 语义与 RS256 完全共享）。
func TestParseSymmetricExpiredAndLeeway(t *testing.T) {
	s := newTestSigner(t)
	token, err := s.Sign(WithSubject("u"), WithTTL(-time.Minute))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	_, err = ParseSymmetric(token, testHS256Secret(t))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("过期令牌必须 wrap ErrInvalidToken, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenExpired) {
		t.Fatalf("过期令牌必须可 Is 到 gojwt.ErrTokenExpired, got %v", err)
	}
	if _, err := ParseSymmetric(token, testHS256Secret(t), WithLeeway(2*time.Minute)); err != nil {
		t.Fatalf("ParseSymmetric() with leeway = %v, want nil", err)
	}
}

// TestAlgConfusionBoundToKeyForm 锁定 #86 核心设计点 1：密钥形态绑定算法——
// RS256 令牌喂 HMAC 入口、HS256 令牌喂 RSA 入口，两个方向都必须在算法白名单处
// 被拒（alg 混淆是 JWT 的经典 CVE 形态，比「一个 Parse 按密钥类型猜」更关死）。
func TestAlgConfusionBoundToKeyForm(t *testing.T) {
	kp := newTestKeyPair(t)
	s := newTestSigner(t)
	rs256Token, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	hs256Token, err := s.Sign(WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	// HMAC 密钥绝不接受 RS256 令牌。
	_, err = ParseSymmetric(rs256Token, testHS256Secret(t))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseSymmetric(RS256 token) 必须拒绝, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenSignatureInvalid) {
		t.Fatalf("alg 白名单拒绝必须可 Is 到 gojwt.ErrTokenSignatureInvalid, got %v", err)
	}
	// 反向：RSA 公钥入口也绝不接受 HS256 令牌。
	if _, err := Parse(hs256Token, kp.Public); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse(HS256 token) 必须拒绝, got %v", err)
	}
}

// TestParseSymmetricRejectsWeakSecret 解析侧同一判据（#86）：与 NewSymmetric 共享
// 同一密钥强度下限，弱密钥不能靠「反正签名也对不上」混过去。
func TestParseSymmetricRejectsWeakSecret(t *testing.T) {
	s := newTestSigner(t)
	token, err := s.Sign(WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ParseSymmetric(token, []byte("short")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseSymmetric() 弱密钥必须拒绝, got %v", err)
	}
}

// TestSymmetricSignRejectsReservedClaimInjection #71 注册声明注入面防护对 HS256
// 同效（两形态共用 signPayload 单一实现）。
func TestSymmetricSignRejectsReservedClaimInjection(t *testing.T) {
	s := newTestSigner(t)
	_, err := s.Sign(WithSubject("u"), WithClaim("exp", "injected"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("WithClaim(exp) 注入必须拒绝, got %v", err)
	}
}

// TestParseSymmetricWithAudience ParseOption（WithAudience fail-closed，#66）对
// HS256 同效（#86 设计点 3：对称与 RSA 共享校验语义）。第三方 IdP 形态令牌用
// gojwt 原生构造（aud string 形态），走的是同一份 claimsFromMap 收集。
func TestParseSymmetricWithAudience(t *testing.T) {
	// aud 是注册声明、不可经 WithClaim 注入（#71），用 gojwt 原生构造带 aud 的
	// 第三方 IdP 产物。
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{"aud": "svc-a"})
	tok.Header = map[string]any{"alg": "HS256"}
	thirdParty, err := tok.SignedString(testHS256Secret(t))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	if _, err := ParseSymmetric(thirdParty, testHS256Secret(t), WithAudience("svc-a")); err != nil {
		t.Fatalf("ParseSymmetric() matching audience = %v, want nil", err)
	}
	// aud 收进 Claims.Audience。
	got, err := ParseSymmetric(thirdParty, testHS256Secret(t), WithAudience("svc-a"))
	if err != nil {
		t.Fatalf("ParseSymmetric() collect error = %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "svc-a" {
		t.Fatalf("Audience = %v, want [svc-a]", got.Audience)
	}
	// 不匹配 ⇒ fail-closed 拒绝。
	if _, err := ParseSymmetric(thirdParty, testHS256Secret(t), WithAudience("svc-b")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("mismatched audience must wrap ErrInvalidToken, got %v", err)
	}
}
