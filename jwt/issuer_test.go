package jwt

import (
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// #95：WithExpectedIssuer 签发者钉定——iss 声明此前「写了但从不校验」，任意
// 签发者的令牌都被接受，与同包 aud 的强制校验口径相反。
func TestParseWithExpectedIssuer(t *testing.T) {
	kp := newTestKeyPair(t)
	good, err := Sign(kp, WithIssuer("self"), WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	noIss, err := Sign(kp, WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() no-iss error = %v", err)
	}
	// 类型异常 iss（注册声明不可经 WithClaim 注入 #71，用 rawClaimsToken 构造）。
	numIss := rawClaimsToken(t, kp, gojwt.MapClaims{"iss": 12345})

	// 匹配 ⇒ 通过，Claims.Issuer 照常读回。
	got, err := Parse(good, kp.Public, WithExpectedIssuer("self"))
	if err != nil {
		t.Fatalf("Parse() matching issuer = %v, want nil", err)
	}
	if got.Issuer != "self" {
		t.Fatalf("Issuer = %q, want self", got.Issuer)
	}
	// 不匹配 ⇒ 拒绝，错误并入 ErrInvalidToken 包装链，底层可 Is 到
	// gojwt.ErrTokenInvalidIssuer（#70 错误链语义）。
	bad, err := Sign(kp, WithIssuer("ATTACKER"), WithSubject("u"))
	if err != nil {
		t.Fatalf("Sign() attacker error = %v", err)
	}
	_, err = Parse(bad, kp.Public, WithExpectedIssuer("self"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() mismatched issuer must wrap ErrInvalidToken, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenInvalidIssuer) {
		t.Fatalf("mismatched issuer must be Is-able to gojwt.ErrTokenInvalidIssuer, got %v", err)
	}
	// fail-closed：令牌无 iss 且配置了期望签发者 ⇒ 拒绝。
	_, err = Parse(noIss, kp.Public, WithExpectedIssuer("self"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() absent iss with expected issuer must wrap ErrInvalidToken, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenRequiredClaimMissing) {
		t.Fatalf("absent iss must be Is-able to gojwt.ErrTokenRequiredClaimMissing, got %v", err)
	}
	// 类型异常 iss ⇒ 拒绝（上游 parseString 报 ErrTokenUnverifiable）。
	_, err = Parse(numIss, kp.Public, WithExpectedIssuer("self"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() type-anomalous iss must wrap ErrInvalidToken, got %v", err)
	}
	// 向后兼容：不配置 WithExpectedIssuer 时不校验 iss，任意 iss 照常通过
	// （既有消费方行为不变；iss 类型异常仍被 #67 拦下）。
	if _, err := Parse(bad, kp.Public); err != nil {
		t.Fatalf("Parse() without issuer check = %v, want nil", err)
	}
	if _, err := Parse(numIss, kp.Public); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Parse() type-anomalous iss without pin must still be rejected (#67), got %v", err)
	}
}

// #95：HS256 共享密钥形态同口径——这正是风险最大的场景：任何持钥方都能签出
// iss 为任意值的令牌，WithExpectedIssuer 把签发者身份钉死。
func TestParseSymmetricWithExpectedIssuer(t *testing.T) {
	s := newTestSigner(t)
	good, err := s.Sign(WithIssuer("self"), WithSubject("u"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ParseSymmetric(good, testHS256Secret(t), WithExpectedIssuer("self")); err != nil {
		t.Fatalf("ParseSymmetric() matching issuer = %v, want nil", err)
	}
	// 同一共享密钥的另一「签发方」签出 iss=ATTACKER 的令牌 ⇒ 拒绝。
	attacker, err := s.Sign(WithIssuer("ATTACKER"), WithSubject("u"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() attacker error = %v", err)
	}
	_, err = ParseSymmetric(attacker, testHS256Secret(t), WithExpectedIssuer("self"))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ParseSymmetric() mismatched issuer must wrap ErrInvalidToken, got %v", err)
	}
	if !errors.Is(err, gojwt.ErrTokenInvalidIssuer) {
		t.Fatalf("mismatched issuer must be Is-able to gojwt.ErrTokenInvalidIssuer, got %v", err)
	}
	// 与 WithAudience 叠加（同一解析器组装，组合使用）。aud 是注册声明、
	// 不可经 WithClaim 注入（#71），用 MapClaims 直接构造模拟第三方签发方。
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"iss": "self", "aud": "svc-a", "exp": gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tok.Header = map[string]any{"alg": "HS256"}
	withAud, err := tok.SignedString(testHS256Secret(t))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	if _, err := ParseSymmetric(withAud, testHS256Secret(t), WithExpectedIssuer("self"), WithAudience("svc-a")); err != nil {
		t.Fatalf("ParseSymmetric() issuer+audience = %v, want nil", err)
	}
}
