// access+refresh 双令牌对原语（#97）：OAuth 事实标准的成对签发/分型校验/refresh
// 轮换此前没有矩阵级口径，下游（如 zeus go-common/jwt）整包坐在 golang-jwt 上
// 手搓——alg 检查还是宽 HMAC（接受 HS256/384/512 任意 HMAC）而非本包的
// WithValidMethods 单算法钉法，同一矩阵两个 JWT 层连算法口径都不一致。本文件把
// token_type 分型声明约定、成对签发、分型校验与 refresh 轮换钩子收编进库层，
// 平台层退役为薄配置（撤销黑名单等有状态部分仍在平台层）。
package jwt

import (
	"fmt"
	"time"

	"github.com/oekit/kitx/uidgen"
)

// TokenTypeClaim 是双令牌对的分型声明名（#97）：Manager 签发的每个令牌都自动
// 携带该声明（值 TokenAccess="access" / TokenRefresh="refresh"），解析后收进
// Claims.Extra。业务声明不得占用该键（reservedClaims，#71 同款注入面防护）。
const TokenTypeClaim = "token_type"

// TokenKind 令牌分型（IssuePair 的产物类型 / ParseTyped 的校验目标）。
type TokenKind string

const (
	// TokenAccess 访问令牌分型（短 ttl，直接面向资源请求）。
	TokenAccess TokenKind = "access"
	// TokenRefresh 刷新令牌分型（长 ttl，只用于换发新令牌对）。
	TokenRefresh TokenKind = "refresh"
)

// withTokenType 内部签发选项：仅供 Manager（#97）盖章分型使用。token_type 为
// 保留声明名（reservedClaims），业务侧不可经 WithClaim 注入；Manager 在 claims
// 平铺之后无条件盖章，杜绝业务声明顶掉分型声明造成分型混淆。
func withTokenType(t string) SignOption { return func(o *signOptions) { o.tokenType = t } }

// managerCodec 是 Manager 对两种签名形态（RS256 密钥对 / HS256 共享密钥）的
// 统一编解码面：签发语义（SignOption）与校验语义（ParseOption/Claims/错误链）
// 完全复用既有原语，Manager 不另立口径。
type managerCodec interface {
	sign(opts ...SignOption) (string, error)
	parse(token string, opts ...ParseOption) (*Claims, error)
}

// rs256Codec 把 RS256 单令牌原语接入 Manager。
type rs256Codec struct{ kp *KeyPair }

func (c rs256Codec) sign(opts ...SignOption) (string, error) { return Sign(c.kp, opts...) }

func (c rs256Codec) parse(token string, opts ...ParseOption) (*Claims, error) {
	return Parse(token, c.kp.Public, opts...)
}

// hs256Codec 把 HS256 单令牌原语接入 Manager。
type hs256Codec struct {
	s      *SymmetricSigner
	secret []byte
}

func (c hs256Codec) sign(opts ...SignOption) (string, error) { return c.s.Sign(opts...) }

func (c hs256Codec) parse(token string, opts ...ParseOption) (*Claims, error) {
	return ParseSymmetric(token, c.secret, opts...)
}

// Manager 是 access+refresh 双令牌管理器：把某一生涯（同一签名密钥）的成对
// 签发（IssuePair）、分型校验（ParseTyped）与 refresh 轮换（Refresh）集中在
// 库层。零内部可变状态，可并发使用。
//
// 形态与单令牌原语一致——两构造器分别绑定 RS256 / HS256，入口钉死单算法
// （WithValidMethods 白名单），Manager 签发/校验的 alg 硬契约与 Sign/Parse、
// SymmetricSigner/ParseSymmetric 完全相同。
//
// 算法配置口说明（#97 审计注记）：**不导出多算法配置口**（HS384/512 等）——
// 「密钥形态绑定单一算法」是防 alg 混淆的硬契约，宽 HMAC 白名单（下游手搓层
// 的现状）正是要收编的反面教材；确需其它算法属新形态，应像 HS256 一样以独立
// 入口 + 独立密钥形态交付，而不是给现有入口开白名单。
type Manager struct {
	codec managerCodec
}

// NewManagerRS256 用 RSA 密钥对构造 RS256 形态 Manager。
//
// 构造期 fail-fast（与 NewSymmetric 同一哲学）：Private 与 Public 任一缺失直接
// 报错——Sign 只需 Private、Parse 只需 Public，Manager 两者都做，缺一半要到
// 第一次签发/校验才炸出来毫无收益（#96 同款对称检查纪律）。
func NewManagerRS256(kp *KeyPair) (*Manager, error) {
	if kp == nil || kp.Private == nil || kp.Public == nil {
		return nil, fmt.Errorf("RS256 Manager 需要完整密钥对（Private/Public 任一缺失拒绝构造）")
	}
	return &Manager{codec: rs256Codec{kp: kp}}, nil
}

// NewManagerHS256 用共享密钥构造 HS256 形态 Manager（密钥强度判据与
// NewSymmetric 完全一致：≥ 32 字节，RFC 7518 §3.2）。
//
// secret 即刻拷贝（#147）：签发路径（hs256Codec.sign → SymmetricSigner.Sign）与
// 校验路径（hs256Codec.parse → ParseSymmetric）必须持有**同一块**密钥材料——
// 此前校验器拿的是调用方原切片，调用方构造后原地改写 buffer（清零、缓冲复用、
// 配置热加载覆盖——安全卫生常见做法，正是 NewSymmetric 注释声明要防的场景）
// 会让 Manager 进入「签得出、验不过」状态。
func NewManagerHS256(secret []byte) (*Manager, error) {
	s, err := NewSymmetric(secret)
	if err != nil {
		return nil, err
	}
	return &Manager{codec: hs256Codec{s: s, secret: append([]byte(nil), secret...)}}, nil
}

// IssuePair 成对签发 access+refresh 双令牌：同 subject，各自带 token_type 分型
// 声明与自动生成的 jti（32 hex，两令牌各自独立，未经显式 WithJTI 覆盖时）。
// ttlAccess / ttlRefresh 分别是两个令牌的有效期（必须为正——配置零值透传签出
// 永不过期令牌是最危险的缺省，与 WithTTL(0) panic（#65）同一纪律，此处以
// error 而非 panic 表达：IssuePair 有 error 出口）。
//
// opts 透传既有 SignOption（如 WithIssuer 钉签发者、WithAudienceClaims 钉受众、
// WithClaim 带会话数据、WithNow/WithIssuedAt 注入签发时钟），两令牌共享同一份
// 选项；其中 subject 与 ttl 由位置参数拍板（用户同名选项 last-wins 覆盖之），
// token_type 由 Manager 盖章（WithClaim("token_type", ...) 直接被 #71 注入面
// 防护拒绝）。
//
// 返回的 access/refresh 都是普通 JWT 字符串：直接用 Parse/ParseSymmetric 也能
// 解（token_type 落在 Extra），但按分型消费请走 ParseTyped——分型校验正是本
// 原语的存在意义。
func (m *Manager) IssuePair(subject string, ttlAccess, ttlRefresh time.Duration, opts ...SignOption) (access, refresh string, err error) {
	// min 内建（Go 1.21+）与「任一非正即拒」等价：ttl 必须为正——配置零值
	// 透传签出永不过期令牌是最危险的缺省（#65 同款纪律，IssuePair 以 error
	// 表达）。
	if min(ttlAccess, ttlRefresh) <= 0 {
		return "", "", fmt.Errorf("IssuePair 的 ttl 必须为正（access=%v refresh=%v）——配置零值透传签出永不过期令牌是最危险的缺省（#65 同款纪律，IssuePair 以 error 表达）", ttlAccess, ttlRefresh)
	}
	access, err = m.issueTyped(TokenAccess, subject, ttlAccess, opts)
	if err != nil {
		return "", "", err
	}
	refresh, err = m.issueTyped(TokenRefresh, subject, ttlRefresh, opts)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// ParseTyped 分型校验并解析令牌：在既有校验语义（签名、exp/nbf、可选 aud/iss
// 钉定，ParseOption 全量透传）之上，额外强制 token_type 分型声明——缺失、非
// 字符串或与期望分型不符一律拒绝（fail-closed）。错误链与 Parse 一致：外层
// ErrInvalidToken 双可 errors.Is。
//
// 非 Manager 签发（无 token_type 声明）的令牌在此一律拒绝：分型校验的前提是
// 令牌自证分型，签名只证明「是我的 key 签的」。
func (m *Manager) ParseTyped(kind TokenKind, token string, opts ...ParseOption) (*Claims, error) {
	if kind != TokenAccess && kind != TokenRefresh {
		return nil, fmt.Errorf("%w: 未知令牌分型 %q（可用 %q / %q）", ErrInvalidToken, string(kind), TokenAccess, TokenRefresh)
	}
	claims, err := m.codec.parse(token, opts...)
	if err != nil {
		return nil, err
	}
	raw, ok := claims.Extra[TokenTypeClaim]
	if !ok {
		return nil, fmt.Errorf("%w: 令牌缺少 %s 声明——非 Manager 签发的令牌不能按分型消费（fail-closed）", ErrInvalidToken, TokenTypeClaim)
	}
	typed, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%w: 声明 %s 类型异常: %T", ErrInvalidToken, TokenTypeClaim, raw)
	}
	if typed != string(kind) {
		return nil, fmt.Errorf("%w: 令牌分型不匹配: %s=%q，期望 %q", ErrInvalidToken, TokenTypeClaim, typed, string(kind))
	}
	return claims, nil
}

// Refresh 用合法 refresh 令牌轮换出新令牌对（refresh token rotation）：分型
// 校验旧令牌（token_type=refresh，ParseOption 经 opts 透传）→ 以旧令牌的
// 身份与会话上下文（sub/iss/aud/业务声明 Extra）签发新对（分型重新盖章、jti
// 重新生成、exp/iat 重新计算）→ 成功后以旧 refresh 的 Claims 调用 onRotate
// 轮换钩子（可为 nil；同步调用，旧令牌的 Claims.ID 即待吊销的 jti）。
//
// 钩子只负责「旧令牌失效化」的落地（撤销黑名单/存储仍在平台层），库层保证
// 时序：新对签发成功之后才触发。轮换语义本身是无状态的——旧 refresh 的作废
// 依赖平台层在钩子里记录 jti 并在后续 ParseTyped 通路外拒绝（库不维护黑名单，
// #97：有状态撤销是平台层的薄配置职责）。
func (m *Manager) Refresh(refreshToken string, ttlAccess, ttlRefresh time.Duration, onRotate func(old *Claims), opts ...ParseOption) (access, refresh string, err error) {
	// min 内建（Go 1.21+）与「任一非正即拒」等价（IssuePair 同口径，#65 纪律）。
	if min(ttlAccess, ttlRefresh) <= 0 {
		return "", "", fmt.Errorf("Refresh 的 ttl 必须为正（access=%v refresh=%v）——配置零值透传签出永不过期令牌是最危险的缺省（#65 同款纪律，Refresh 以 error 表达）", ttlAccess, ttlRefresh)
	}
	old, err := m.ParseTyped(TokenRefresh, refreshToken, opts...)
	if err != nil {
		return "", "", err
	}
	// 继承会话上下文：iss/sub/aud/业务声明。token_type 分型由 issueTyped 重新
	// 盖章，不随 Extra 继承。jti 一律重新生成——轮换不得复用旧 jti（钩子正是
	// 按旧 jti 吊销，复用等于吊销新令牌）。aud 随身份走（#117）：多受众部署的
	// WithAudience（#66）fail-closed 校验会把丢 aud 的新令牌全部拒掉，轮换即
	// 断流。nbf 不随轮换继承——exp/iat 既已按轮换时刻重新计算，生效窗口整体
	// 重开，新令牌自签发时刻起生效。
	base := make([]SignOption, 0, len(old.Extra)+3)
	if old.Issuer != "" {
		base = append(base, WithIssuer(old.Issuer))
	}
	// aud 继承前过滤空串（#148）：old.Audience 是运行期从令牌解出的内容，不是
	// 调用方配置——WithAudienceClaims 是构造期 fail-fast（空受众 panic，#117），
	// 喂运行期数据等于让令牌内容（HS256 共享密钥形态下同密钥任一签发方可造
	// aud:[""]）击穿请求链。空受众在 WithAudience（#66）fail-closed 校验下永不
	// 匹配，过滤丢弃不缩小可匹配面；全为空串则不继承 aud（零参与不设置同效）。
	if aud := nonEmptyAud(old.Audience); len(aud) > 0 {
		base = append(base, WithAudienceClaims(aud...))
	}
	for k, v := range old.Extra {
		if k == TokenTypeClaim {
			continue
		}
		base = append(base, WithClaim(k, v))
	}
	access, err = m.issueTyped(TokenAccess, old.Subject, ttlAccess, base)
	if err != nil {
		return "", "", err
	}
	refresh, err = m.issueTyped(TokenRefresh, old.Subject, ttlRefresh, base)
	if err != nil {
		return "", "", err
	}
	if onRotate != nil {
		onRotate(old)
	}
	return access, refresh, nil
}

// issueTyped 签发单枚带分型的令牌：用户选项在前，位置参数（subject/ttl）与
// 分型盖章在后（last-wins，Manager 拍板）；用户未显式 WithJTI 时由库层自动
// 生成（jti 出口集中在库层，#97）。
func (m *Manager) issueTyped(kind TokenKind, subject string, ttl time.Duration, opts []SignOption) (string, error) {
	all := make([]SignOption, 0, len(opts)+4)
	all = append(all, opts...)
	all = append(all, WithSubject(subject), WithTTL(ttl), withTokenType(string(kind)))
	if !setsJTI(opts) {
		jti, err := uidgen.RandomHexE(16)
		if err != nil {
			return "", fmt.Errorf("生成 jti: %w", err)
		}
		all = append(all, WithJTI(jti))
	}
	return m.codec.sign(all...)
}

// setsJTI 探测用户选项是否显式设置了 jti（显式值优先于自动生成）。
// 选项是纯赋值闭包，探测式应用与真实签发同效；WithTTL(0)/WithNow(nil) 之类
// 的 panic 选项在探测时同样 panic，与直接签发的可观测行为一致。
func setsJTI(opts []SignOption) bool {
	probe := &signOptions{claims: map[string]any{}}
	for _, opt := range opts {
		opt(probe)
	}
	return probe.jti != ""
}

// nonEmptyAud 过滤受众里的空串（Refresh 的 aud 继承专用，#148）。
func nonEmptyAud(aud []string) []string {
	out := make([]string, 0, len(aud))
	for _, a := range aud {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}
