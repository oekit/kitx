// 清零战役回归护栏（#139/#147/#148/#149，2026-11-12 sweep）：每条修复配套的
// 行为钉子，防止后续演进回退。
package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// craftRS256Token 用指定密钥对签一枚任意 claims 的 RS256 令牌（探针工具）。
func craftRS256Token(t *testing.T, kp *KeyPair, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	s, err := tok.SignedString(kp.Private)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return s
}

// craftHS256Token 用指定共享密钥签一枚任意 claims 的 HS256 令牌（探针工具）。
func craftHS256Token(t *testing.T, secret []byte, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return s
}

// #139：HS256 空密钥签发分支必须有哨兵错误面（ErrInvalidToken 可 errors.Is），
// 与 RS256 形态的 Sign/Parse 错误链对称；此前裸 error 无包前缀无哨兵。
func TestHS256SignEmptySecretSentinel(t *testing.T) {
	var nilSigner *SymmetricSigner
	for _, tc := range []struct {
		name   string
		signer *SymmetricSigner
	}{
		{"nil 接收者", nilSigner},
		{"零值空密钥", &SymmetricSigner{}},
	} {
		_, err := tc.signer.Sign()
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("[%s] Sign 必须包 ErrInvalidToken 哨兵（#139），got %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), "缺少 HS256 共享密钥") {
			t.Fatalf("[%s] 错误文案应保留密钥缺失诊断，got %v", tc.name, err)
		}
	}
}

// #139：ParseSymmetric 的 checkSecret 包装改双 %w——外层哨兵可 Is、内层错误链
// 不再被 %v 拍平（#70 双 %w 纪律补漏）。
func TestParseSymmetricWeakSecretSentinel(t *testing.T) {
	_, err := ParseSymmetric("whatever", []byte("short"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseSymmetric 弱密钥必须包 ErrInvalidToken（#139），got %v", err)
	}
	if !strings.Contains(err.Error(), "RFC 7518") {
		t.Fatalf("错误文案应保留密钥强度诊断，got %v", err)
	}
}

// #147：NewManagerHS256 必须拷贝 secret——签发与校验持同一块密钥材料。调用方
// 构造后原地改写 buffer（清零/缓冲复用/配置热加载是安全卫生常见做法），
// Manager 自签令牌必须仍能自己校验通过；此前校验器拿调用方原切片，
// 改写后「签得出、验不过」。
func TestNewManagerHS256SecretCopied(t *testing.T) {
	sec := testHS256Secret(t)
	m, err := NewManagerHS256(sec)
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	access, _, err := m.IssuePair("user-1", 10*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	// 调用方原地改写共享底层数组。
	for i := range sec {
		sec[i] = 0
	}
	if _, err := m.ParseTyped(TokenAccess, access); err != nil {
		t.Fatalf("改写调用方 buffer 后 Manager 自签令牌必须仍可校验（#147），got %v", err)
	}
}

// #148：Refresh 把运行期从令牌解出的 aud 喂进构造期 fail-fast 的
// WithAudienceClaims ⇒ aud 含空串即 panic（HS256 同密钥任一签发方均可造，
// 令牌内容可触发）。修复后：非空受众照常继承、空串过滤丢弃、全空串不继承
// aud（零参与不设置同效），运行期不再 panic。
func TestRefreshSurvivesEmptyAudienceClaim(t *testing.T) {
	sec := testHS256Secret(t)
	m, err := NewManagerHS256(sec)
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	now := time.Now()
	for _, tc := range []struct {
		name    string
		aud     any
		wantAud []string
	}{
		{"aud 为空串", "", nil},
		{"aud 数组含空串", []any{"", "svc-a"}, []string{"svc-a"}},
	} {
		token := craftHS256Token(t, sec, gojwt.MapClaims{
			"sub":        "user-1",
			"iat":        now.Unix(),
			"exp":        now.Add(time.Hour).Unix(),
			"token_type": string(TokenRefresh),
			"aud":        tc.aud,
		})
		// 对照组：解析侧对这类令牌完全正常（此前非法值是 Refresh 这步才
		// 升级成 panic 的）。
		if _, err := m.ParseTyped(TokenRefresh, token); err != nil {
			t.Fatalf("[%s] ParseTyped(refresh) error = %v", tc.name, err)
		}
		var access, refresh string
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] Refresh panicked: %v（#148：运行期 aud 不得击穿请求链）", tc.name, r)
				}
			}()
			access, refresh, err = m.Refresh(token, 10*time.Minute, time.Hour, nil)
		}()
		if err != nil {
			t.Fatalf("[%s] Refresh() error = %v", tc.name, err)
		}
		ac, err := m.ParseTyped(TokenAccess, access)
		if err != nil {
			t.Fatalf("[%s] ParseTyped(access) error = %v", tc.name, err)
		}
		if len(ac.Audience) != len(tc.wantAud) {
			t.Fatalf("[%s] access Audience = %v, want %v", tc.name, ac.Audience, tc.wantAud)
		}
		for i, want := range tc.wantAud {
			if ac.Audience[i] != want {
				t.Fatalf("[%s] access Audience = %v, want %v", tc.name, ac.Audience, tc.wantAud)
			}
		}
		// 轮换出的 refresh 令牌同样可用（旋转链不断）。
		if _, err := m.ParseTyped(TokenRefresh, refresh); err != nil {
			t.Fatalf("[%s] ParseTyped(new refresh) error = %v", tc.name, err)
		}
	}
}

// #149：exp=0 与缺 exp 在库眼里都是「无 exp」——Claims.ExpiresAt 必须同形（nil），
// 与上游 golang-jwt parseNumericDate（0 视作「无此声明」）口径对齐；此前
// mapTime 只判类型不判零值，exp=0 产出 1970 纪元，消费方的
// 「ExpiresAt != nil 即已过期」判据被反转。iat/nbf 共用 mapTime，零值同口径。
func TestMapTimeZeroValueIsNil(t *testing.T) {
	kp := newTestKeyPair(t)
	now := time.Now()

	// 缺省强制 exp（#135）口径：exp=0 被上游按「无 exp」拒绝。
	probe := craftRS256Token(t, kp, gojwt.MapClaims{
		"sub": "user-1",
		"iat": now.Unix(),
		"exp": 0,
	})
	if _, err := Parse(probe, kp.Public); err == nil {
		t.Fatal("exp=0 在缺省强制 exp 口径下必须拒绝（与缺 exp 同判）")
	}

	// WithAllowNoExpiry 豁免放行后：ExpiresAt 必须为 nil（与缺 exp 同形），
	// 不再是 1970 纪元。
	claims, err := Parse(probe, kp.Public, WithAllowNoExpiry())
	if err != nil {
		t.Fatalf("Parse(exp=0, WithAllowNoExpiry) error = %v", err)
	}
	if claims.ExpiresAt != nil {
		t.Fatalf("exp=0 ⇒ ExpiresAt 必须为 nil（#149 上游口径），got %v", claims.ExpiresAt)
	}

	// iat=0 / nbf=0 同口径：nil 而非 1970 纪元。
	probe2 := craftRS256Token(t, kp, gojwt.MapClaims{
		"sub": "user-1",
		"iat": 0,
		"nbf": 0,
		"exp": now.Add(time.Hour).Unix(),
	})
	claims2, err := Parse(probe2, kp.Public)
	if err != nil {
		t.Fatalf("Parse(iat=0, nbf=0) error = %v", err)
	}
	if claims2.IssuedAt != nil || claims2.NotBefore != nil {
		t.Fatalf("iat=0/nbf=0 ⇒ 必须为 nil（#149 同口径），got iat=%v nbf=%v", claims2.IssuedAt, claims2.NotBefore)
	}
}
