package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/oekit/kitx/authz"
	"github.com/oekit/kitx/jwt"
	"github.com/oekit/kitx/uidgen"
	"github.com/oekit/logx"
)

// log 是本包的懒解析日志器（SDK/基础包规范：Delegating，禁止 Default()）。
var log = logx.Delegating("kitx/auth")

// User 是认证流的最小用户快照：登录方备好（IssuePair 消费），轮换期由
// UserRepo 重新拉取（角色变更随轮换生效）。
type User struct {
	// ID 用户标识（签发为 sub）。
	ID string
	// Roles 角色集（注入 rolesClaim 声明；空集不注入）。
	Roles []string
	// Claims 业务会话声明（随令牌签发并随轮换继承——jwt 业务声明口径）。
	// 不得占用 rolesClaim 键（Roles 是角色的唯一入口）与 jwt 保留声明
	// （iss/sub/aud/exp/nbf/iat/jti/token_type，#71 注入面防护在 jwt 层）。
	Claims map[string]any
}

// SessionMeta 是会话登记的登录上下文（设备/网络维度，管理端枚举与审计用）。
// 收拢成结构体而非位置参数（ip, ua string）：字段随审计需求增长时签名不漂
// （#120 的漂移教训在 API 形状上同样适用）。
type SessionMeta struct {
	// IP 登录来源 IP（可空）。
	IP string
	// Device 设备标识（可空；同账号多端登录的辨识键）。
	Device string
	// UA 登录客户端 UA（可空）。
	UA string
}

// UserRepo 是用户仓储适配面（#120）：下游只留本接口的实现，编排语义单点在
// 库层。
type UserRepo interface {
	// GetByID 拉取用户快照。错误分型契约（#120 不变式）：查无此人必须返回
	// ErrUserNotFound（Flow 归 401，不泄露存在性）；其余错误原样上抛（归
	// 500）。返回 (nil, nil) 视为违约（归 500）。
	GetByID(ctx context.Context, id string) (*User, error)
	// RoleIDs 拉取角色集（轮换期单独拉——角色变更随轮换生效）。出错原样
	// 上抛（归 500）。
	RoleIDs(ctx context.Context, id string) ([]string, error)
	// TouchLogin 登录活跃度回写。**尽力而为**（#120 不变式）：失败不阻断
	// 轮换，Flow 只记日志。
	TouchLogin(ctx context.Context, id string) error
}

// TokenPair 是签发产物：双令牌 + 已登记的会话快照。
type TokenPair struct {
	// Access access 令牌（短 ttl，面向资源请求）。
	Access string
	// Refresh refresh 令牌（长 ttl，只用于换发新令牌对）。
	Refresh string
	// Session 已登记的会话（ID/哈希/登录时刻——登记失败则整个签发失败）。
	Session authz.Session
}

// Flow 是认证流编排器：把签发尾段（IssuePair）、refresh 轮换（RotateRefresh）、
// 登出撤销（Logout）、改密吊销钩子（RevokeUser）集中在库层。构造后零可变
// 状态，可并发使用。
type Flow struct {
	jwt        *jwt.Manager
	sessions   authz.SessionRegistry
	revoker    authz.Revoker
	ttlAccess  time.Duration
	ttlRefresh time.Duration
	rolesClaim string
	signOpts   []jwt.SignOption
	parseOpts  []jwt.ParseOption
	now        func() time.Time
}

// FlowOption 是 NewFlow 的函数选项。
type FlowOption func(*Flow)

// WithTTL 配置双令牌寿命（必须显式配置为正——配置零值透传签出永不过期令牌
// 是最危险的缺省，jwt #65 同款纪律，NewFlow 以 error 表达）。ttlRefresh 必须
// ≥ ttlAccess：会话登记/拉黑 TTL 以 refresh 寿命为两令牌寿命的上界，短于
// access 会让强踢漏拉黑尚能活的 access。
func WithTTL(access, refresh time.Duration) FlowOption {
	return func(f *Flow) {
		f.ttlAccess = access
		f.ttlRefresh = refresh
	}
}

// WithRolesClaim 配置角色声明键（空串回退默认 "roles"）。
func WithRolesClaim(key string) FlowOption {
	return func(f *Flow) {
		if key != "" {
			f.rolesClaim = key
		}
	}
}

// WithClock 注入 Flow 时钟（会话 LoginAt；f 为 nil 直接 panic，jwt.WithNow
// 同款纪律）。签发时钟（iat/exp）经 WithSignOptions 传 jwt.WithNow/WithIssuedAt。
func WithClock(f func() time.Time) FlowOption {
	return func(fl *Flow) {
		if f == nil {
			panic("auth: WithClock 的时钟函数不能为 nil——静默回落 time.Now() 会让时钟无声漂移")
		}
		fl.now = f
	}
}

// WithSignOptions 配置共享签发选项（WithIssuer 钉签发者、WithAudienceClaims
// 钉受众、WithNow/WithIssuedAt 注入签发时钟等），两令牌共享。**不得**含
// WithJTI（Manager.IssuePair 的显式 jti 会盖到两枚令牌上，破坏 jti 唯一性；
// jti 由库层自动生成）。选项入参 slices.Clone 拷贝（jwt #117 同款）。
func WithSignOptions(opts ...jwt.SignOption) FlowOption {
	return func(f *Flow) {
		f.signOpts = append(slices.Clone(f.signOpts), opts...)
	}
}

// WithParseOptions 配置共享解析选项（WithAudience（#66 fail-closed）、
// WithExpectedIssuer（#95）、WithLeeway 等），解析/轮换/登出全路径生效。
// 选项入参 slices.Clone 拷贝。
func WithParseOptions(opts ...jwt.ParseOption) FlowOption {
	return func(f *Flow) {
		f.parseOpts = append(slices.Clone(f.parseOpts), opts...)
	}
}

// NewFlow 构造认证流编排器。构造期 fail-fast（jwt.NewManagerRS256 同一哲学）：
// 依赖任一缺失、TTL 未配置/非正、ttlRefresh < ttlAccess 直接报错——这些零值
// 透传到第一次签发/轮换才炸出来毫无收益。
func NewFlow(m *jwt.Manager, sessions authz.SessionRegistry, rev authz.Revoker, opts ...FlowOption) (*Flow, error) {
	if m == nil || sessions == nil || rev == nil {
		return nil, fmt.Errorf("auth: NewFlow 需要非 nil 的 jwt.Manager / SessionRegistry / Revoker")
	}
	f := &Flow{
		jwt:        m,
		sessions:   sessions,
		revoker:    rev,
		rolesClaim: "roles",
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(f)
	}
	if min(f.ttlAccess, f.ttlRefresh) <= 0 {
		return nil, fmt.Errorf("auth: 双令牌 TTL 必须显式配置为正（access=%v refresh=%v）——配置零值透传签出永不过期令牌是最危险的缺省（jwt #65 同款纪律）", f.ttlAccess, f.ttlRefresh)
	}
	if f.ttlRefresh < f.ttlAccess {
		return nil, fmt.Errorf("auth: ttlRefresh(%v) 必须 ≥ ttlAccess(%v)——会话登记/拉黑 TTL 以 refresh 寿命为两令牌寿命的上界", f.ttlRefresh, f.ttlAccess)
	}
	return f, nil
}

// IssuePair 签发尾段（#120）：成对签发 access+refresh（kitx/jwt Manager
// IssuePair，token_type 分型 + 独立 jti）并登记在线会话（设备/会话维度）。
//
// 不变式：**签发与登记一次落地**——会话登记失败时把刚签出的双令牌直接拉黑
// 再上抛（宁可失败重试，不放行一对「签了名但不可吊销」的无主令牌）。
func (f *Flow) IssuePair(ctx context.Context, u *User, meta SessionMeta) (*TokenPair, error) {
	if u == nil || u.ID == "" {
		return nil, fmt.Errorf("auth: IssuePair 的用户快照必须带 ID")
	}
	return f.issueTail(ctx, u, meta)
}

// RotateRefresh refresh 轮换 + 防重放（#120 核心不变式）：
//
//  1. 分型校验旧 refresh（ParseTyped，ParseOption 透传）；
//  2. 双层撤销判定：用户级截断命中 ⇒ ErrUnauthorized（改密/风控的账号级
//     吊销，覆盖重放分型——账号级事件优先于令牌级事件）；否则 token 级黑名
//     单命中 ⇒ ErrReplayed（已换出/已登出/已强踢的 refresh 二次使用，重放
//     信号）；
//  3. 会话认领前置（GetByRefreshHash：旧 refresh 必须仍挂在活会话上）；
//  4. GetByID 错误分型（ErrUserNotFound ⇒ 401；其余 ⇒ 500），RoleIDs 重取
//     （角色变更随轮换生效）；
//  5. **原子认领旧会话**（Kick，先拉黑双 hash 后删键）：恰一个轮换胜出，
//     败方/被强踢者 ⇒ ErrReplayed——旧 refresh 单次使用不靠时序运气；
//  6. 签发新对并登记新会话（issueTail）；
//  7. TouchLogin 尽力而为（失败只记日志）。
//
// 时序拍板（与 Manager.Refresh 的差异）：**先认领后签发**——Manager.Refresh
// 的 onRotate 钩子在签发之后触发，满足不了认领闸（并发轮换会双双签发成功）；
// 认领先行的代价是「认领成功但签发失败 ⇒ 需重新登录」（fail-closed，宁可
// 重登也不留旧令牌复活窗口）。
//
// 错误链：401 类（ErrUnauthorized/ErrReplayed/jwt.ErrInvalidToken 三向
// errors.Is）；500 类原样上抛不带 ErrUnauthorized。
func (f *Flow) RotateRefresh(ctx context.Context, repo UserRepo, refresh string, meta SessionMeta) (*TokenPair, *User, error) {
	if repo == nil {
		return nil, nil, fmt.Errorf("auth: RotateRefresh 需要非 nil UserRepo")
	}
	claims, err := f.jwt.ParseTyped(jwt.TokenRefresh, refresh, slices.Clone(f.parseOpts)...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if claims.Subject == "" {
		return nil, nil, fmt.Errorf("%w: refresh 缺少 sub，无法定位用户", ErrUnauthorized)
	}
	// 撤销判定（见方法契约第 2 条：用户级命中优先于 token 级，账号级事件
	// 覆盖重放分型）。
	if revoked, err := f.revoker.RevokedUser(ctx, claims.Subject, iatOf(claims)); err != nil {
		return nil, nil, fmt.Errorf("auth: 用户级撤销查询失败: %w", err)
	} else if revoked {
		return nil, nil, fmt.Errorf("%w: 用户级撤销（改密/风控）", ErrUnauthorized)
	}
	if revoked, err := authz.RevokedToken(ctx, f.revoker, refresh); err != nil {
		return nil, nil, fmt.Errorf("auth: 撤销查询失败: %w", err)
	} else if revoked {
		return nil, nil, fmt.Errorf("%w: 旧 refresh 已在撤销黑名单", ErrReplayed)
	}
	old, err := f.sessions.GetByRefreshHash(ctx, authz.TokenHash(refresh))
	if err != nil {
		if errors.Is(err, authz.ErrSessionNotFound) {
			// 会话不在 = 已轮换/已强踢/已登出后的二次使用，或会话自然过期——
			// 按重放拒绝（fail-closed）。
			return nil, nil, fmt.Errorf("%w: 会话不在登记表", ErrReplayed)
		}
		return nil, nil, fmt.Errorf("auth: 查询会话失败: %w", err)
	}
	user, err := repo.GetByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		return nil, nil, fmt.Errorf("auth: 查询用户失败: %w", err)
	}
	if user == nil || user.ID == "" {
		return nil, nil, fmt.Errorf("auth: GetByID 违约（nil/空 ID 用户）——查无此人请返回 ErrUserNotFound")
	}
	roles, err := repo.RoleIDs(ctx, user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: 查询角色失败: %w", err)
	}

	// 原子认领旧会话（防重放拍板点，见方法契约第 5 条）。
	kicked, err := f.sessions.Kick(ctx, old.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: 旧会话下线失败: %w", err)
	}
	if !kicked {
		return nil, nil, fmt.Errorf("%w: 旧会话已被并发轮换/强踢认领", ErrReplayed)
	}

	u := &User{ID: user.ID, Roles: roles, Claims: user.Claims}
	pair, err := f.issueTail(ctx, u, meta)
	if err != nil {
		// 旧会话已下线（fail-closed）：客户端重新登录。新令牌的无主残留由
		// issueTail 自身回收（拉黑）。
		return nil, nil, err
	}
	if err := repo.TouchLogin(ctx, user.ID); err != nil {
		log.CtxWarn(ctx, "TouchLogin failed (best-effort, ignored)",
			"user_id", user.ID, logx.ErrKey, err)
	}
	return pair, u, nil
}

// Logout 登出撤销（#120）：双 token 一次落地——会话下线（Kick：双 hash 拉黑
// + 删键）+ 呈现令牌直接拉黑（覆盖会话外/旧对的令牌，TTL 取配置寿命上界，
// 宁长勿短）。幂等：会话/令牌已不在照常成功。多步失败 errors.Join 聚合。
func (f *Flow) Logout(ctx context.Context, access, refresh string) error {
	var errs []error
	if s, err := f.sessions.GetByRefreshHash(ctx, authz.TokenHash(refresh)); err != nil {
		if !errors.Is(err, authz.ErrSessionNotFound) {
			errs = append(errs, fmt.Errorf("auth: 查询会话失败: %w", err))
		}
	} else if _, err := f.sessions.Kick(ctx, s.ID); err != nil {
		errs = append(errs, fmt.Errorf("auth: 会话下线失败: %w", err))
	}
	errs = append(errs, f.revokePair(ctx, "auth: 登出", access, refresh))
	return errors.Join(errs...)
}

// RevokeUser 用户级吊销编排（#121 改密陈旧吊销钩子；风控「封禁下线」同口）：
//
//  1. authz.Revoker.RevokeUser 截断点（at 之前签发的令牌判陈旧，落 #119
//     用户级撤销黑名单）——覆盖未登记/跨实例的存量令牌；
//  2. authz.SessionRegistry.KickUser 全会话强踢（双 hash 拉黑 + 删键）——
//     在线会话立即下线，不等陈旧判定逐请求拦截。
//
// 两步失败 errors.Join 聚合（部分落地也要报全，调用方决定重试口径）。
// at 取改密时刻（pwd.ApplyExpiryOnLogin/改密路径同源）。
func RevokeUser(ctx context.Context, rev authz.Revoker, sessions authz.SessionRegistry, userID string, at time.Time) error {
	if rev == nil || sessions == nil {
		return fmt.Errorf("auth: RevokeUser 需要非 nil Revoker / SessionRegistry")
	}
	if userID == "" {
		return fmt.Errorf("auth: RevokeUser 的 userID 不能为空")
	}
	var errs []error
	if err := rev.RevokeUser(ctx, userID, at); err != nil {
		errs = append(errs, fmt.Errorf("auth: 用户级截断失败: %w", err))
	}
	if _, err := sessions.KickUser(ctx, userID); err != nil {
		errs = append(errs, fmt.Errorf("auth: 强踢全会话失败: %w", err))
	}
	return errors.Join(errs...)
}

// RevokeUser 是 Flow 装配形态的改密吊销钩子（见包级 RevokeUser）。
func (f *Flow) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	return RevokeUser(ctx, f.revoker, f.sessions, userID, at)
}

// IsRevoked 组合撤销判定（#119 与 jwt 校验面的组合锚点）：token 级黑名单
// （TokenHash 键）或用户级截断（iat 陈旧，pwd.TokenStaleBefore 口径）任一
// 命中即真。查询故障原样上抛（消费侧归 500——不放行、不放大 401）。
func IsRevoked(ctx context.Context, rev authz.Revoker, token, userID string, iat time.Time) (bool, error) {
	if rev == nil {
		return false, fmt.Errorf("auth: IsRevoked 需要非 nil Revoker")
	}
	if hit, err := rev.Revoked(ctx, authz.TokenHash(token)); err != nil {
		return false, fmt.Errorf("auth: 撤销查询失败: %w", err)
	} else if hit {
		return true, nil
	}
	if hit, err := rev.RevokedUser(ctx, userID, iat); err != nil {
		return false, fmt.Errorf("auth: 用户级撤销查询失败: %w", err)
	} else if hit {
		return true, nil
	}
	return false, nil
}

// ParseAccess 资源侧消费面（#119「与 jwt 校验面可组合」的落地）：分型校验
// （ParseTyped access，ParseOption 在共享解析选项后追加、按调用项生效）+
// 双层撤销判定，返回 Claims。
//
// 错误分型：校验失败/已吊销 ⇒ ErrUnauthorized 链（401）；撤销查询故障 ⇒
// 原样上抛（500）。
func (f *Flow) ParseAccess(ctx context.Context, access string, opts ...jwt.ParseOption) (*jwt.Claims, error) {
	all := make([]jwt.ParseOption, 0, len(f.parseOpts)+len(opts))
	all = append(all, f.parseOpts...)
	all = append(all, opts...)
	claims, err := f.jwt.ParseTyped(jwt.TokenAccess, access, all...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if err := f.checkRevoked(ctx, access, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkRevoked 双层撤销判定的共享出口（401 分型在此收口）。
func (f *Flow) checkRevoked(ctx context.Context, token string, claims *jwt.Claims) error {
	revoked, err := IsRevoked(ctx, f.revoker, token, claims.Subject, iatOf(claims))
	if err != nil {
		return err // 存储故障：归 500（既不放行也不放大 401）
	}
	if revoked {
		return fmt.Errorf("%w: 令牌已吊销", ErrUnauthorized)
	}
	return nil
}

// iatOf 取签发时刻（无 iat 声明 ⇒ 零值——用户级陈旧判定 fail-closed 侧）。
func iatOf(claims *jwt.Claims) time.Time {
	if claims == nil || claims.IssuedAt == nil {
		return time.Time{}
	}
	return claims.IssuedAt.Time
}

// issueTail 签发 + 登记的共享尾段（IssuePair 与 RotateRefresh 同一份时序）。
func (f *Flow) issueTail(ctx context.Context, u *User, meta SessionMeta) (*TokenPair, error) {
	if _, ok := u.Claims[f.rolesClaim]; ok {
		return nil, fmt.Errorf("auth: 用户 Claims 不得占用角色声明键 %q——Roles 字段是角色的唯一入口（#71 同款注入面纪律）", f.rolesClaim)
	}
	opts := make([]jwt.SignOption, 0, len(f.signOpts)+len(u.Claims)+2)
	opts = append(opts, f.signOpts...)
	for k, v := range u.Claims {
		opts = append(opts, jwt.WithClaim(k, v))
	}
	if len(u.Roles) > 0 {
		opts = append(opts, jwt.WithClaim(f.rolesClaim, slices.Clone(u.Roles)))
	}
	access, refresh, err := f.jwt.IssuePair(u.ID, f.ttlAccess, f.ttlRefresh, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth: 签发令牌对失败: %w", err)
	}
	// 回读 refresh 取 jti（Manager.IssuePair 的自动 jti 各自独立，会话登记
	// 需要 refresh 的 jti 对账；签发产物自证，回读只做提取）。
	rc, err := f.jwt.ParseTyped(jwt.TokenRefresh, refresh, slices.Clone(f.parseOpts)...)
	if err != nil {
		return nil, fmt.Errorf("auth: 回读签发产物失败: %w", err)
	}
	sid, err := newSessionID()
	if err != nil {
		revokeErr := f.revokePair(ctx, "auth: 回收无主令牌", access, refresh)
		return nil, errors.Join(err, revokeErr)
	}
	sess := authz.Session{
		ID:          sid,
		UserID:      u.ID,
		Device:      meta.Device,
		IP:          meta.IP,
		UA:          meta.UA,
		RefreshJTI:  rc.ID,
		AccessHash:  authz.TokenHash(access),
		RefreshHash: authz.TokenHash(refresh),
		LoginAt:     f.now(),
	}
	if err := f.sessions.Register(ctx, sess, f.ttlRefresh); err != nil {
		// 签发与登记一次落地（IssuePair 契约）：登记失败回收刚签的双令牌，
		// 不放行无主（不可强踢）的令牌对。
		revokeErr := f.revokePair(ctx, "auth: 回收无主令牌", access, refresh)
		return nil, errors.Join(fmt.Errorf("auth: 会话登记失败: %w", err), revokeErr)
	}
	return &TokenPair{Access: access, Refresh: refresh, Session: sess}, nil
}

// revokePair 双令牌拉黑的单点实现（#131：Logout 的呈现令牌拉黑与 issueTail
// 失败路径的无主令牌回收共用同一份「access→ttlAccess / refresh→ttlRefresh」
// TTL 口径——改 ttl 语义不再需要同步两处）。op 是错误前缀，标识调用路径；
// access/refresh 为空串跳过该路；拉黑失败 errors.Join 聚合（错误链 %w 保留）。
func (f *Flow) revokePair(ctx context.Context, op, access, refresh string) error {
	var errs []error
	if access != "" {
		if err := authz.RevokeToken(ctx, f.revoker, access, f.ttlAccess); err != nil {
			errs = append(errs, fmt.Errorf("%s: 拉黑 access 失败: %w", op, err))
		}
	}
	if refresh != "" {
		if err := authz.RevokeToken(ctx, f.revoker, refresh, f.ttlRefresh); err != nil {
			errs = append(errs, fmt.Errorf("%s: 拉黑 refresh 失败: %w", op, err))
		}
	}
	return errors.Join(errs...)
}

// newSessionID 生成会话 ID（32 hex，uidgen 集中随机出口；rand 故障显式上抛
// ——会话 ID 不可降级（空 ID 会撞登记主键），也不 panic（请求路径有 error
// 出口就走 error，uidgen #87 同哲学）。
func newSessionID() (string, error) {
	id, err := uidgen.RandomHexE(16)
	if err != nil {
		return "", fmt.Errorf("auth: 生成会话 ID 失败（crypto/rand 故障）: %w", err)
	}
	return id, nil
}
