// Package jwt 提供 RS256 的 JWT 签发与校验。
//
// 硬契约（与既有消费方互通，不可改）：
//   - alg 恰为 RS256
//   - JWT header 只含 {"alg":"RS256"}，不带 typ
//   - 业务自定义声明平铺进 payload，解析时收集进 Claims.Extra
package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken 表示令牌无法解析或校验失败。
var ErrInvalidToken = errors.New("jwt: invalid token")

// Claims 是签发与解析的载荷容器。
type Claims struct {
	gojwt.RegisteredClaims
	// Extra 承载业务自定义声明（签发时经 WithClaim 平铺进 payload，解析时收集回来）。
	Extra map[string]any
}

// signOptions 是签发选项的内部表示。
type signOptions struct {
	issuer    string
	subject   string
	jti       string
	ttl       time.Duration
	noExpiry  bool
	notBefore *time.Time
	claims    map[string]any
	nowFn     func() time.Time
}

// SignOption 是 Sign 的函数选项。
type SignOption func(*signOptions)

// WithIssuer 设置 iss。
func WithIssuer(iss string) SignOption { return func(o *signOptions) { o.issuer = iss } }

// WithSubject 设置 sub。
func WithSubject(sub string) SignOption { return func(o *signOptions) { o.subject = sub } }

// WithJTI 设置 jti（令牌 ID）。
func WithJTI(jti string) SignOption { return func(o *signOptions) { o.jti = jti } }

// WithTTL 设置 exp = iat + ttl。d 为 0 直接 panic（#65）：显式 0 与「未设置」
// 不可区分，而最可能的成因是「配置缺失的零值透传」——静默接受等于放行一批
// 永不过期的凭据，与 uidgen.RandomHex 拒绝空串密钥（#50）同款纪律。确需无
// 过期令牌请显式 WithNoExpiry。负值不拦（既有消费方用负 ttl 构造已过期令牌
// 做校验测试）。
func WithTTL(d time.Duration) SignOption {
	return func(o *signOptions) {
		if d == 0 {
			panic("jwt: WithTTL(0)——永不过期令牌是最危险的缺省（多为配置零值透传），确需无过期令牌请显式 WithNoExpiry()（#65）")
		}
		o.ttl = d
		o.noExpiry = false // last-wins：WithNoExpiry 之后再 WithTTL 恢复写 exp
	}
}

// WithNoExpiry 显式签发无 exp 的令牌（#65）：名字本身即审计信号，grep 得到。
// 无 exp 令牌一旦泄漏没有自然失效路径，仅供确有轮换/吊销机制的场景；与
// WithTTL 并用时后应用的生效。
func WithNoExpiry() SignOption { return func(o *signOptions) { o.noExpiry = true } }

// WithNotBefore 设置 nbf。
func WithNotBefore(t time.Time) SignOption { return func(o *signOptions) { o.notBefore = &t } }

// WithNow 注入签发时钟：iat = now()、exp = iat + ttl 同钟源（nbf 仍取
// WithNotBefore 的绝对时刻）。缺省 time.Now（#64：缺省行为不变）；f 为 nil
// 直接 panic——静默回落真实时钟会让 iat 无声漂移。测试可注入假时钟获得
// 确定性令牌，不再只能断言 iat≈now 的区间。
func WithNow(f func() time.Time) SignOption {
	return func(o *signOptions) {
		if f == nil {
			panic("jwt: WithNow 的时钟函数不能为 nil——静默回落 time.Now() 会让 iat 无声漂移（#64）")
		}
		o.nowFn = f
	}
}

// WithIssuedAt 显式设置签发时刻：iat = t、exp = t + ttl，等价于 WithNow(
// 固定返回 t)。带显式签发时刻的签发面（如消费方 Issue(..., now time.Time)
// 参数形态）委托本包时用它透传 now，缺省行为不变（#64）。
func WithIssuedAt(t time.Time) SignOption {
	return func(o *signOptions) { o.nowFn = func() time.Time { return t } }
}

// WithClaim 追加一个业务自定义声明。
func WithClaim(key string, val any) SignOption {
	return func(o *signOptions) { o.claims[key] = val }
}

// Sign 用 RS256 签发令牌。缺省 iat = time.Now()、ttl = 24h；可用 WithNow/
// WithIssuedAt 注入签发时刻（iat 与 exp 同钟源），WithNoExpiry 显式去掉 exp。
func Sign(kp *KeyPair, opts ...SignOption) (string, error) {
	if kp == nil || kp.Private == nil {
		return "", fmt.Errorf("%w: 缺少私钥", ErrInvalidToken)
	}
	o := &signOptions{ttl: 24 * time.Hour, claims: map[string]any{}, nowFn: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	now := o.nowFn()
	payload := map[string]any{}
	if o.issuer != "" {
		payload["iss"] = o.issuer
	}
	if o.subject != "" {
		payload["sub"] = o.subject
	}
	if o.jti != "" {
		payload["jti"] = o.jti
	}
	if !o.noExpiry {
		payload["exp"] = now.Add(o.ttl).Unix()
	}
	payload["iat"] = now.Unix()
	if o.notBefore != nil {
		payload["nbf"] = o.notBefore.Unix()
	}
	for k, v := range o.claims {
		payload[k] = v
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(payload))
	tok.Header = map[string]any{"alg": "RS256"} // 硬契约：header 只含 alg
	return tok.SignedString(kp.Private)
}

// parseOptions 是解析选项的内部表示。
type parseOptions struct {
	leeway   time.Duration
	audience []string
}

// ParseOption 是 Parse 的函数选项。
type ParseOption func(*parseOptions)

// WithLeeway 设置时钟偏移容忍。
func WithLeeway(d time.Duration) ParseOption { return func(o *parseOptions) { o.leeway = d } }

// WithAudience 设置期望受众（#66）：令牌 aud 命中任一即通过；令牌无 aud 时
// 拒绝（fail-closed）。不设置时不校验 aud（向后兼容）——签名校验只证明
// 「是我的 key 签的」，不证明「是签给我的」；同密钥多受众场景必须显式配置。
func WithAudience(expected ...string) ParseOption {
	return func(o *parseOptions) { o.audience = expected }
}

// Parse 校验并解析令牌（RS256-only，缺省零 leeway、不校验 aud）。
//
// 已注册声明（iss/sub/aud/jti/exp/iat/nbf）收进 RegisteredClaims；其余进 Extra。
// iss/sub/jti 存在但非字符串时拒绝（#67）：RFC 7519 §4.1.1/§4.1.2 要求 iss/sub
// MUST be a String，类型异常即规格违规令牌，fail-closed 而非静默归零放行
// （golang-jwt 上游 MapClaims.GetSubject 对类型异常同样返回错误）；声明缺失
// 维持零值不报错——缺失声明的令牌按消费方自身的校验责任走。
func Parse(token string, pub *rsa.PublicKey, opts ...ParseOption) (*Claims, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: 缺少公钥", ErrInvalidToken)
	}
	o := &parseOptions{}
	for _, opt := range opts {
		opt(o)
	}
	parserOpts := []gojwt.ParserOption{
		gojwt.WithValidMethods([]string{"RS256"}),
		gojwt.WithLeeway(o.leeway),
	}
	if len(o.audience) > 0 {
		parserOpts = append(parserOpts, gojwt.WithAudience(o.audience...))
	}
	parser := gojwt.NewParser(parserOpts...)
	tok, err := parser.Parse(token, func(t *gojwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	mc, ok := tok.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: 载荷类型异常", ErrInvalidToken)
	}
	iss, err := mapStr(mc, "iss")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	sub, err := mapStr(mc, "sub")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	jti, err := mapStr(mc, "jti")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	out := &Claims{Extra: map[string]any{}}
	out.RegisteredClaims = gojwt.RegisteredClaims{
		Issuer:    iss,
		Subject:   sub,
		ID:        jti,
		ExpiresAt: mapTime(mc, "exp"),
		IssuedAt:  mapTime(mc, "iat"),
		NotBefore: mapTime(mc, "nbf"),
	}
	if aud, ok := mc["aud"]; ok {
		if s, ok := aud.(string); ok {
			out.Audience = gojwt.ClaimStrings{s}
		} else {
			out.Audience = gojwt.ClaimStrings{}
			if arr, ok := aud.([]any); ok {
				for _, a := range arr {
					if s, ok := a.(string); ok {
						out.Audience = append(out.Audience, s)
					}
				}
			}
		}
	}
	for k, v := range mc {
		switch k {
		case "iss", "sub", "jti", "exp", "iat", "nbf", "aud":
		default:
			out.Extra[k] = v
		}
	}
	return out, nil
}

// mapStr 取 string 声明（#67）：缺失返回 ("", nil)——缺失按消费方自身的校验
// 责任走，不报错；存在但非字符串返回错误（带声明名与实际类型，如
// 「声明 sub 类型异常: float64」）——数值 sub（部分第三方 provider 与 Java 侧
// Long 序列化产物）静默归零成空 Subject 放行，比拒绝更危险。
func mapStr(mc gojwt.MapClaims, key string) (string, error) {
	v, ok := mc[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("声明 %s 类型异常: %T", key, v)
	}
	return s, nil
}

// mapTime 取数字时间声明（缺失或类型异常返回 nil）。
func mapTime(mc gojwt.MapClaims, key string) *gojwt.NumericDate {
	v, ok := mc[key]
	if !ok {
		return nil
	}
	switch n := v.(type) {
	case float64:
		return gojwt.NewNumericDate(time.Unix(int64(n), 0))
	case int64:
		return gojwt.NewNumericDate(time.Unix(n, 0))
	default:
		return nil
	}
}
