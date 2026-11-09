package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func newTestRS256Manager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManagerRS256(newTestKeyPair(t))
	if err != nil {
		t.Fatalf("NewManagerRS256() error = %v", err)
	}
	return m
}

// 构造期 fail-fast：密钥形态不完整的 Manager 必须当场报错（与 NewSymmetric
// 同一哲学；#96 同款对称检查纪律——Sign 只需 Private、Parse 只需 Public，
// Manager 两者都做）。
func TestNewManagerFailFast(t *testing.T) {
	kp := newTestKeyPair(t)
	for name, bad := range map[string]*KeyPair{
		"nil":          nil,
		"private-only": {Private: kp.Private},
		"public-only":  {Public: kp.Public},
		"empty":        {},
	} {
		if _, err := NewManagerRS256(bad); err == nil {
			t.Fatalf("NewManagerRS256 [%s] 必须报错", name)
		}
	}
	for name, secret := range map[string][]byte{
		"nil": nil,
		"6字节": []byte("secret"),
	} {
		if _, err := NewManagerHS256(secret); err == nil {
			t.Fatalf("NewManagerHS256 [%s] 必须报错（与 NewSymmetric 同一判据）", name)
		}
	}
	if _, err := NewManagerHS256(testHS256Secret(t)); err != nil {
		t.Fatalf("NewManagerHS256() error = %v, want nil", err)
	}
}

// IssuePair 往返（RS256）：分型声明、自动 jti、subject、ttl 全部落位；header
// 硬契约不变；plain Parse 仍可解（向后兼容，token_type 落 Extra）。
func TestIssuePairRS256RoundTrip(t *testing.T) {
	m := newTestRS256Manager(t)
	access, refresh, err := m.IssuePair("user-1", 10*time.Minute, time.Hour,
		WithIssuer("self"), WithClaim("un", "alice"))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	// header 硬契约：两枚令牌都只含 alg。
	for name, tok := range map[string]string{"access": access, "refresh": refresh} {
		hdr := decodeSegment(t, tok, 0)
		if hdr["alg"] != "RS256" {
			t.Fatalf("[%s] header[alg] = %v, want RS256", name, hdr["alg"])
		}
		if _, ok := hdr["typ"]; ok {
			t.Fatalf("[%s] header must not contain typ", name)
		}
	}
	// 分型校验读回。
	ac, err := m.ParseTyped(TokenAccess, access)
	if err != nil {
		t.Fatalf("ParseTyped(access) error = %v", err)
	}
	if ac.Subject != "user-1" || ac.Issuer != "self" {
		t.Fatalf("access claims = {iss:%q sub:%q}, want {self user-1}", ac.Issuer, ac.Subject)
	}
	if ac.Extra[TokenTypeClaim] != string(TokenAccess) {
		t.Fatalf("access token_type = %v, want %q", ac.Extra[TokenTypeClaim], TokenAccess)
	}
	if ac.Extra["un"] != "alice" {
		t.Fatalf("access Extra[un] = %v, want alice（WithClaim 透传两令牌）", ac.Extra["un"])
	}
	rc, err := m.ParseTyped(TokenRefresh, refresh)
	if err != nil {
		t.Fatalf("ParseTyped(refresh) error = %v", err)
	}
	if rc.Subject != "user-1" || rc.Extra[TokenTypeClaim] != string(TokenRefresh) {
		t.Fatalf("refresh claims 异常: sub=%q token_type=%v", rc.Subject, rc.Extra[TokenTypeClaim])
	}
	// jti 出口：自动生成、非空、两令牌互不相同。
	if ac.ID == "" || rc.ID == "" {
		t.Fatalf("jti 必须自动生成: access=%q refresh=%q", ac.ID, rc.ID)
	}
	if ac.ID == rc.ID {
		t.Fatalf("access/refresh jti 不得相同: %q", ac.ID)
	}
	// ttl 分型落位：access exp-iat = 10m、refresh exp-iat = 1h。
	if got := ac.ExpiresAt.Unix() - ac.IssuedAt.Unix(); got != int64(10*time.Minute/time.Second) {
		t.Fatalf("access exp-iat = %d, want 600", got)
	}
	if got := rc.ExpiresAt.Unix() - rc.IssuedAt.Unix(); got != int64(time.Hour/time.Second) {
		t.Fatalf("refresh exp-iat = %d, want 3600", got)
	}
	// 向后兼容：plain Parse 照常可解（token_type 只是不再进 RegisteredClaims
	// 之外的通道，仍落 Extra）。
	if _, err := Parse(access, m.codec.(rs256Codec).kp.Public); err != nil {
		t.Fatalf("plain Parse() on pair token = %v, want nil", err)
	}
}

// IssuePair 往返（HS256）：共享密钥形态同一语义。
func TestIssuePairHS256RoundTrip(t *testing.T) {
	m, err := NewManagerHS256(testHS256Secret(t))
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	access, refresh, err := m.IssuePair("user-2", time.Minute, 30*time.Minute)
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	for name, tok := range map[string]string{"access": access, "refresh": refresh} {
		if hdr := decodeSegment(t, tok, 0); hdr["alg"] != "HS256" {
			t.Fatalf("[%s] header[alg] = %v, want HS256", name, hdr["alg"])
		}
	}
	if _, err := m.ParseTyped(TokenAccess, access, WithExpectedIssuer("")); err != nil {
		t.Fatalf("ParseTyped(access) error = %v", err)
	}
	rc, err := m.ParseTyped(TokenRefresh, refresh)
	if err != nil {
		t.Fatalf("ParseTyped(refresh) error = %v", err)
	}
	if rc.Subject != "user-2" || rc.Extra[TokenTypeClaim] != string(TokenRefresh) {
		t.Fatalf("refresh claims 异常: sub=%q token_type=%v", rc.Subject, rc.Extra[TokenTypeClaim])
	}
}

// 分型校验 fail-closed：交叉分型拒绝；非 Manager 签发（无 token_type 声明）拒绝；
// 未知分型入口拒绝；token_type 声明不可经 WithClaim 伪造（#71+#97 注入面）。
func TestParseTypedFailClosed(t *testing.T) {
	m := newTestRS256Manager(t)
	access, refresh, err := m.IssuePair("u", time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	// 交叉分型。
	if _, err := m.ParseTyped(TokenRefresh, access); err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseTyped(refresh, access token) must wrap ErrInvalidToken, got %v", err)
	}
	if _, err := m.ParseTyped(TokenAccess, refresh); err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseTyped(access, refresh token) must wrap ErrInvalidToken, got %v", err)
	}
	// 非 Manager 签发（同 key、无 token_type 声明）⇒ 拒绝。
	untyped, err := Sign(m.codec.(rs256Codec).kp, WithSubject("u"), WithTTL(time.Minute))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	_, err = m.ParseTyped(TokenAccess, untyped)
	if err == nil || !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), TokenTypeClaim) {
		t.Fatalf("ParseTyped() on untyped token must reject mentioning %s, got %v", TokenTypeClaim, err)
	}
	// 类型异常 token_type ⇒ 拒绝（模拟异常签发方）。
	weird := rawClaimsToken(t, m.codec.(rs256Codec).kp, gojwt.MapClaims{
		"token_type": 123, "exp": gojwt.NewNumericDate(time.Now().Add(time.Minute)),
	})
	if _, err := m.ParseTyped(TokenAccess, weird); err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseTyped() on type-anomalous token_type must wrap ErrInvalidToken, got %v", err)
	}
	// 未知分型入口。
	if _, err := m.ParseTyped("bogus", access); err == nil {
		t.Fatal("ParseTyped(bogus kind) must reject")
	}
	// WithClaim 注入 token_type 被 #71 防护拒绝（分型不可伪造）。
	if _, err := Sign(m.codec.(rs256Codec).kp, WithClaim(TokenTypeClaim, string(TokenRefresh))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Sign(WithClaim(token_type)) must wrap ErrInvalidToken, got %v", err)
	}
}

// ttl 必须为正：配置零值透传签出永不过期令牌是最危险的缺省（#65 同款纪律）。
func TestIssuePairRejectsNonPositiveTTL(t *testing.T) {
	m := newTestRS256Manager(t)
	cases := []struct {
		name string
		a, r time.Duration
	}{
		{"access零值", 0, time.Minute},
		{"refresh零值", time.Minute, 0},
		{"双零值", 0, 0},
		{"负值", -time.Minute, time.Minute},
	}
	for _, tc := range cases {
		if _, _, err := m.IssuePair("u", tc.a, tc.r); err == nil {
			t.Fatalf("IssuePair [%s] 必须报错", tc.name)
		}
	}
}

// 显式 WithJTI 优先于自动生成（两令牌共享同一份选项 ⇒ 同 jti，行为确定性钉住）。
func TestIssuePairRespectsExplicitJTI(t *testing.T) {
	m := newTestRS256Manager(t)
	access, refresh, err := m.IssuePair("u", time.Minute, time.Minute, WithJTI("fixed-jti"))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	ac, err := m.ParseTyped(TokenAccess, access)
	if err != nil {
		t.Fatalf("ParseTyped(access) error = %v", err)
	}
	rc, err := m.ParseTyped(TokenRefresh, refresh)
	if err != nil {
		t.Fatalf("ParseTyped(refresh) error = %v", err)
	}
	if ac.ID != "fixed-jti" || rc.ID != "fixed-jti" {
		t.Fatalf("explicit WithJTI must win: access=%q refresh=%q, want fixed-jti", ac.ID, rc.ID)
	}
}

// Refresh 轮换：旧 refresh 换新对；身份/签发者/会话声明继承；jti 重新生成；
// 钩子在成功后拿到旧 claims（按旧 jti 吊销）；错误路径不触发钩子。
func TestRefreshRotation(t *testing.T) {
	m := newTestRS256Manager(t)
	var hookCalled int
	var hookOld *Claims
	hook := func(old *Claims) { hookCalled++; hookOld = old }

	access1, refresh1, err := m.IssuePair("user-1", 10*time.Minute, time.Hour,
		WithIssuer("self"), WithClaim("session", "s-1"), WithClaim("mfa", true))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	access2, refresh2, err := m.Refresh(refresh1, 10*time.Minute, time.Hour, hook)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	// 新对分型有效、身份与会话上下文继承。
	ac2, err := m.ParseTyped(TokenAccess, access2)
	if err != nil {
		t.Fatalf("ParseTyped(access2) error = %v", err)
	}
	if ac2.Subject != "user-1" || ac2.Issuer != "self" {
		t.Fatalf("access2 = {iss:%q sub:%q}, want {self user-1}（轮换继承身份）", ac2.Issuer, ac2.Subject)
	}
	if ac2.Extra["session"] != "s-1" || ac2.Extra["mfa"] != true {
		t.Fatalf("access2 Extra = %v, want 会话声明继承", ac2.Extra)
	}
	rc2, err := m.ParseTyped(TokenRefresh, refresh2)
	if err != nil {
		t.Fatalf("ParseTyped(refresh2) error = %v", err)
	}
	// jti 重新生成（不复用旧 jti）。
	rc1, err := m.ParseTyped(TokenRefresh, refresh1)
	if err != nil {
		t.Fatalf("ParseTyped(refresh1) error = %v", err)
	}
	if rc1.ID == rc2.ID || ac2.ID == rc2.ID {
		t.Fatalf("轮换后 jti 必须全新: old=%q new=%q", rc1.ID, rc2.ID)
	}
	// 钩子时序：成功后触发一次，拿到旧 refresh 的 claims（jti 出口）。
	if hookCalled != 1 || hookOld == nil || hookOld.ID != rc1.ID {
		t.Fatalf("hook: called=%d old=%v, want 1 次且携带旧 refresh jti %q", hookCalled, hookOld, rc1.ID)
	}
	// onRotate 为 nil 合法。
	if _, _, err := m.Refresh(refresh2, time.Minute, time.Minute, nil); err != nil {
		t.Fatalf("Refresh(nil hook) error = %v", err)
	}
	// access 令牌不能用于轮换（分型校验）。
	hookCalled = 0
	if _, _, err := m.Refresh(access1, time.Minute, time.Minute, hook); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Refresh(access token) must wrap ErrInvalidToken, got %v", err)
	}
	if hookCalled != 0 {
		t.Fatalf("失败路径不得触发轮换钩子, called=%d", hookCalled)
	}
	// 垃圾令牌拒绝。
	if _, _, err := m.Refresh("not-a-token", time.Minute, time.Minute, hook); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Refresh(garbage) must wrap ErrInvalidToken, got %v", err)
	}
}

// Refresh 拒绝过期 refresh；ParseOption（WithLeeway）经 Refresh 透传生效；
// ttl 位置参数校验同 IssuePair。
func TestRefreshValidation(t *testing.T) {
	m := newTestRS256Manager(t)
	// 过期 refresh：签发时钟注入到 1 小时前、refresh ttl 仅 10 分钟。
	past := time.Now().Add(-time.Hour)
	_, expired, err := m.IssuePair("u", time.Second, 10*time.Minute, WithNow(func() time.Time { return past }))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	if _, _, err := m.Refresh(expired, time.Minute, time.Minute, nil); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Refresh(expired refresh) must wrap ErrInvalidToken, got %v", err)
	}
	// WithLeeway 经 opts 透传：容忍 2 小时偏移后同一令牌可轮换。
	if _, _, err := m.Refresh(expired, time.Minute, time.Minute, nil, WithLeeway(2*time.Hour)); err != nil {
		t.Fatalf("Refresh(expired, WithLeeway) = %v, want nil（ParseOption 透传）", err)
	}
	// ttl 校验。
	if _, _, err := m.Refresh(expired, 0, time.Minute, nil); err == nil {
		t.Fatal("Refresh 零值 ttl 必须报错")
	}
}
