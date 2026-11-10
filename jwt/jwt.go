// Package jwt 提供 JWT 签发与校验，覆盖两种主流形态：RS256（非对称密钥对，
// Sign/Parse）与 HS256（对称共享密钥，SymmetricSigner/ParseSymmetric，#86）。
// 两形态之上另有 access+refresh 双令牌对原语（Manager：成对签发 IssuePair、
// 分型校验 ParseTyped、refresh 轮换 Refresh，#97）。
//
// 两形态共享同一套 SignOption/ParseOption/Claims 与校验语义；每个入口固定自己
// 的算法（RS256 入口只认 RS256、HS256 入口只认 HS256），密钥形态绑定算法关死
// alg 混淆。解析侧校验入口：WithAudience（#66）与 WithExpectedIssuer（#95）；
// 签发侧 aud 出口：WithAudienceClaims（#117）——与 WithAudience 闭环，库签发的
// 令牌可带 aud，多受众部署不再被迫手搓 payload。
//
// 硬契约（与既有消费方互通，不可改）：
//   - RS256 形态 alg 恰为 RS256；HS256 形态 alg 恰为 HS256
//   - JWT header 只含 {"alg":"<alg>"}，不带 typ
//   - 业务自定义声明平铺进 payload，解析时收集进 Claims.Extra
package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"sort"
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
	audience  []string
	ttl       time.Duration
	noExpiry  bool
	notBefore *time.Time
	claims    map[string]any
	nowFn     func() time.Time
	tokenType string
}

// SignOption 是 Sign 的函数选项。
type SignOption func(*signOptions)

// WithIssuer 设置 iss。
func WithIssuer(iss string) SignOption { return func(o *signOptions) { o.issuer = iss } }

// WithSubject 设置 sub。
func WithSubject(sub string) SignOption { return func(o *signOptions) { o.subject = sub } }

// WithAudienceClaims 设置 aud（受众）（#117）：单受众写 string 形态、多受众写
// []string 形态，与 claimsFromMap 的解析面（string/数组双收）对称（RFC 7519
// §4.1.3 双形态）。不设置时令牌不带 aud（向后兼容）；零参与不设置同效（显式
// 回退默认值）；受众含空串直接 panic——空受众是配置零值透传的最常见形态，签出
// 的令牌在 WithAudience（#66）fail-closed 校验下永不匹配，静默接受等于批量产出
// 必被拒的令牌（WithTTL(0) panic（#65）同款纪律）。重复调用 last-wins（与
// WithIssuer 等注册声明选项同口径）。入参即刻 slices.Clone 拷贝，调用方事后
// 改写原切片不影响签发结果。
//
// 名字不是 WithAudience：解析侧已有 WithAudience(...string) ParseOption（校验
// 期望受众），Go 不允许同名重载，此处取「写入 aud 声明」语义与之分型（与
// WithExpectedIssuer（#95）同款命名分型纪律）。aud 是保留声明（reservedClaims），
// 不可经 WithClaim 注入（#71）——本选项是 aud 的唯一签发出口。
func WithAudienceClaims(aud ...string) SignOption {
	return func(o *signOptions) {
		for _, a := range aud {
			if a == "" {
				panic("jwt: WithAudienceClaims 的受众不能是空串——空受众是配置零值透传的最常见形态，签出的令牌在 WithAudience（#66）fail-closed 校验下永不匹配（#117）")
			}
		}
		o.audience = slices.Clone(aud)
	}
}

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

// reservedClaims 是保留声明名：RFC 7519 §4.1 注册声明 + token_type（#97 双令牌
// 分型保留名）。kitx/jwt 为它们提供专属签发通道（WithIssuer/WithSubject/
// WithAudienceClaims/WithJTI/WithNotBefore；exp/iat 由 WithTTL/WithNoExpiry 与
// 签发时钟派生；token_type 由 Manager 盖章），业务声明不得占用这些键。
var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"token_type": {},
}

// WithClaim 追加一个业务自定义声明。
//
// 保留声明（iss/sub/aud/exp/nbf/iat/jti，及 #97 起的双令牌分型名 token_type）
// 不可经 WithClaim 注入，注入时 Sign 直接报错（#71）：Sign 先写保留声明、最后
// 平铺 claims，无条件覆盖会让 WithClaim("exp", ...) 顶掉过期时间、
// WithClaim("iss", externalInput) 篡改签发者、WithClaim("token_type", ...)
// 伪造分型——claim key 若来自配置/请求拼接，就是令牌声明注入面。注册声明请用
// WithIssuer/WithSubject/WithAudienceClaims/WithJTI/WithNotBefore 设置，
// exp/iat 由 WithTTL 与签发时钟派生，token_type 由 Manager（#97）盖章。
func WithClaim(key string, val any) SignOption {
	return func(o *signOptions) { o.claims[key] = val }
}

// Sign 用 RS256 签发令牌。缺省 iat = time.Now()、ttl = 24h；可用 WithNow/
// WithIssuedAt 注入签发时刻（iat 与 exp 同钟源），WithNoExpiry 显式去掉 exp。
// 对称形态（HS256 共享密钥）见 SymmetricSigner（#86）。
func Sign(kp *KeyPair, opts ...SignOption) (string, error) {
	if kp == nil || kp.Private == nil {
		return "", fmt.Errorf("%w: 缺少私钥", ErrInvalidToken)
	}
	payload, err := signPayload(opts)
	if err != nil {
		return "", err
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(payload))
	tok.Header = map[string]any{"alg": "RS256"} // 硬契约：header 只含 alg
	return tok.SignedString(kp.Private)
}

// signPayload 应用签发选项并组装 payload（#86：RS256/HS256 两形态共用同一份签发
// 语义——缺省 ttl=24h、iat/exp 同钟源派生、注册声明注入面防护 #71）。
func signPayload(opts []SignOption) (map[string]any, error) {
	o := &signOptions{ttl: 24 * time.Hour, claims: map[string]any{}, nowFn: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	// 保留声明注入面 fail-closed（#71）：claims 平铺在保留声明写入之后、
	// 无条件覆盖，注入保留键 = 顶掉 exp/iss/iat 等的既定值（#97 起 token_type
	// 同样保留——伪造分型即分型混淆注入面）。
	if hits := reservedClaimHits(o.claims); len(hits) > 0 {
		return nil, fmt.Errorf("%w: WithClaim 不能注入保留声明 %v（#71）——这是令牌声明注入面；注册声明请用 WithIssuer/WithSubject/WithAudienceClaims/WithJTI/WithNotBefore 设置，exp/iat 由 WithTTL 与签发时钟派生，token_type 由 Manager 盖章（#97）", ErrInvalidToken, hits)
	}
	now := o.nowFn()
	payload := map[string]any{}
	if o.issuer != "" {
		payload["iss"] = o.issuer
	}
	if o.subject != "" {
		payload["sub"] = o.subject
	}
	// aud 双形态（#117）：单受众 string、多受众 []string——与 claimsFromMap
	// 的解析面对称（RFC 7519 §4.1.3 两形态都合法）。aud 的唯一写入口是
	// WithAudienceClaims；WithClaim("aud") 仍被上面的保留声明防护拒绝（#71
	// 注入面不动）。
	switch len(o.audience) {
	case 0:
	case 1:
		payload["aud"] = o.audience[0]
	default:
		payload["aud"] = o.audience
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
	if o.tokenType != "" {
		// 双令牌分型盖章（#97）：claims 平铺之后无条件写入——业务声明顶不掉，
		// plain Sign（tokenType 为空）保持不带该声明，payload 向后兼容。
		payload["token_type"] = o.tokenType
	}
	return payload, nil
}

// parseOptions 是解析选项的内部表示。
type parseOptions struct {
	leeway   time.Duration
	audience []string
	issuer   string
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

// WithExpectedIssuer 设置期望签发者（#95）：令牌 iss 必须与之严格相等才通过；
// 令牌无 iss 或 iss 不匹配 ⇒ 拒绝（fail-closed）。不设置时不校验 iss（向后
// 兼容）——与 WithAudience 同一口径：签名校验只证明「是我的 key 签的」，不
// 证明「是约定的签发方签的」；共享密钥（HS256）多签发方场景下，任意持钥方
// 都能签出 iss 为任意值的令牌，必须显式钉住来源。
//
// 名字不是 WithIssuer：签发侧已有 WithIssuer(iss) SignOption（写入 iss），
// Go 不允许同名重载；解析侧取「期望」语义与 WithAudience（期望受众）对称。
// 上游 golang-jwt 的校验是严格相等 + iss 必须存在（缺失报
// ErrTokenRequiredClaimMissing、不匹配报 ErrTokenInvalidIssuer、类型异常报
// ErrTokenUnverifiable，均可经错误链 errors.Is，#70）。
func WithExpectedIssuer(expected string) ParseOption {
	return func(o *parseOptions) { o.issuer = expected }
}

// Parse 校验并解析令牌（RS256-only，缺省零 leeway、不校验 aud/iss）。对称形态
// （HS256 共享密钥）见 ParseSymmetric（#86）——两入口共享校验语义。
//
// 错误链保留（#70）：失败时外层哨兵 ErrInvalidToken 与 gojwt 底层 sentinel
// （ErrTokenExpired/ErrTokenSignatureInvalid/ErrTokenNotValidYet 等）同时可
// errors.Is——业务侧可据此分流「过期→走刷新、签名坏→踢下线」。
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
	tok, err := newParser(o, "RS256").Parse(token, func(t *gojwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		// 双 %w 保留底层错误链（#70）：外层可 Is 到 ErrInvalidToken，同时
		// gojwt 的 ErrTokenExpired/ErrTokenSignatureInvalid 等 sentinel 也
		// 可 Is——业务侧「过期→走刷新、签名坏→踢下线」的分流依赖它。%v 会
		// 把链拍平成纯文本，两类令牌不可区分。
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	mc, ok := tok.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: 载荷类型异常", ErrInvalidToken)
	}
	return claimsFromMap(mc)
}

// newParser 构造解析器（#86：入口绑定算法——单算法 WithValidMethods 白名单，
// RS256 入口只认 RS256、HS256 入口只认 HS256，密钥形态绑定算法关死 alg 混淆）。
func newParser(o *parseOptions, alg string) *gojwt.Parser {
	parserOpts := []gojwt.ParserOption{
		gojwt.WithValidMethods([]string{alg}),
		gojwt.WithLeeway(o.leeway),
	}
	if len(o.audience) > 0 {
		parserOpts = append(parserOpts, gojwt.WithAudience(o.audience...))
	}
	if o.issuer != "" {
		parserOpts = append(parserOpts, gojwt.WithIssuer(o.issuer))
	}
	return gojwt.NewParser(parserOpts...)
}

// claimsFromMap 把 MapClaims 收进 Claims（#86：RS256/HS256 两入口共享同一份
// claims 收集与类型校验语义——#67 类型异常 fail-closed、#70 错误链对两形态同效）。
func claimsFromMap(mc gojwt.MapClaims) (*Claims, error) {
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

// reservedClaimHits 返回 claims 里命中注册声明名的键（排序，报错文案确定）。
func reservedClaimHits(claims map[string]any) []string {
	var hits []string
	for k := range claims {
		if _, ok := reservedClaims[k]; ok {
			hits = append(hits, k)
		}
	}
	sort.Strings(hits)
	return hits
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
