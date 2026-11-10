package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/oekit/kitx/pwd"
)

// TokenHash 计算令牌哈希键：sha256(token) 的小写 hex（#119 建议形态）。
//
// 这是撤销黑名单/会话注册表键空间的**唯一产出口**：所有按令牌定位的键
// （黑名单条目、会话 AccessHash/RefreshHash）都必须经本函数派生，下游不再
// 各写一份 sha256 口径——两份拷贝靠注释对齐、漂移即强踢失效（#119 下游实证）。
// 入参是完整令牌串而非 jti：绑定到具体令牌形态（同一 jti 的两个令牌串不同、
// 哈希不同，可分别吊销）。
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Revoker 撤销黑名单存储面（#119）：token 级 + 用户级两层，接口化存储。
//
// 键纪律：hash 参数必须出自 TokenHash（键空间唯一产出口），实现按「键即
// TokenHash 产物」理解与建索引，不接受任意字符串键。原始令牌串入口见
// RevokeToken / RevokedToken 助手。raw token 与 hash 的分型是有意为之：
// 会话注册表（Kick 双 hash 拉黑）只持有 hash，轮换/登出路径未必持有原始串，
// 签名收窄到 hash 级可杜绝「随手传非 TokenHash 键污染键空间」。
//
// 两层语义：
//
//   - token 级（Revoke/Revoked）：单枚令牌拉黑。remaining 是该令牌的**剩余
//     寿命**（条目 TTL，过期自然出清——过期令牌本就被 exp 拒绝，条目无需
//     长生）；已过期令牌不需要登记。
//   - 用户级（RevokeUser/RevokedUser）：截断点。at 之前签发的全部令牌判陈旧
//     （#121 改密陈旧吊销的落地口）。截断点**单调不回退**（同用户重复设置取
//     时间较大者——回退会让已判陈旧的令牌复活，是 fail-open）；不设 TTL（陈旧
//     判定随 iat 天然自限，条目随用户数线性）。
//
// 陈旧判定口径单点在 pwd.TokenStaleBefore（秒截断比较：iat 与截断点同秒不判
// 陈旧）——实现 RevokedUser 必须复用该口径，禁止另写一份比较。
//
// 存储故障契约：实现出错必须返回 error，**不得**把故障折叠成「未吊销」放行
// （fail-open 是黑名单最危险的缺省）。消费侧（kitx/auth）把查询故障归 500：
// 既不放行、也不放大成 401 全站踢下线。
type Revoker interface {
	// Revoke 吊销单枚令牌：以 hash 记黑名单，条目 TTL=remaining。
	// remaining 必须为正（已过期令牌无需登记，非正 TTL 是配置零值透传的
	// 常见形态，#65 同款纪律）。
	Revoke(ctx context.Context, hash string, remaining time.Duration) error
	// Revoked 判定单枚令牌是否已吊销（token 级）。
	Revoked(ctx context.Context, hash string) (bool, error)
	// RevokeUser 用户级吊销：at 之前签发的该用户令牌全部判陈旧（截断点单调不回退）。
	RevokeUser(ctx context.Context, userID string, at time.Time) error
	// RevokedUser 用户级判定：iat 早于截断点（秒截断，pwd.TokenStaleBefore
	// 口径）即陈旧。无截断点 ⇒ false。
	RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error)
}

// RevokeToken 以原始令牌串登记撤销（Revoker.Revoke 的薄助手：内部经
// TokenHash 落到键空间）。remaining 语义同 Revoker.Revoke。
func RevokeToken(ctx context.Context, r Revoker, token string, remaining time.Duration) error {
	return r.Revoke(ctx, TokenHash(token), remaining)
}

// RevokedToken 以原始令牌串判定撤销（Revoker.Revoked 的薄助手）。
func RevokedToken(ctx context.Context, r Revoker, token string) (bool, error) {
	return r.Revoked(ctx, TokenHash(token))
}

// MemRevoker 是 Revoker 的内存实现：并发安全（mutex 保护），零第三方依赖。
//
// 定位：单实例进程内部署的内存形态，兼作契约测试替身（#119 建议形态的
// MapRevoker 角色）。持久形态（Redis 等）由下游按 Revoker 契约落地——键前缀
// 可配、条目 TTL 语义与本实现一致。
//
// 生命周期：不启动后台 goroutine（本仓禁止裸 go func）。token 级条目过期后
// 读判即视为不在；写路径不自动清扫，Sweep 可手动回收过期条目（pkg/cache
// NoBackgroundSweep 同款哲学：清扫时机交给部署形态）。
type MemRevoker struct {
	mu     sync.RWMutex
	hashes map[string]time.Time // hash → 失效时刻（now+remaining）
	users  map[string]time.Time // userID → 用户级截断点（单调不回退）
	now    func() time.Time
}

// MemRevokerOption 是 NewMemRevoker 的函数选项。
type MemRevokerOption func(*MemRevoker)

// WithRevokerClock 注入 MemRevoker 时钟（测试确定性 TTL 边界；f 为 nil 直接
// panic——静默回落 time.Now() 会让时钟无声漂移，WithNow（#64）同款纪律）。
func WithRevokerClock(f func() time.Time) MemRevokerOption {
	return func(m *MemRevoker) {
		if f == nil {
			panic("authz: WithRevokerClock 的时钟函数不能为 nil——静默回落 time.Now() 会让时钟无声漂移")
		}
		m.now = f
	}
}

// NewMemRevoker 构造内存撤销黑名单（缺省时钟 time.Now）。
func NewMemRevoker(opts ...MemRevokerOption) *MemRevoker {
	m := &MemRevoker{
		hashes: make(map[string]time.Time),
		users:  make(map[string]time.Time),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Revoke 登记一条 token 级撤销（TTL=remaining）。
func (m *MemRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if hash == "" {
		return fmt.Errorf("authz: Revoke 的 hash 不能为空——键必须出自 TokenHash")
	}
	if remaining <= 0 {
		return fmt.Errorf("authz: Revoke 的 remaining 必须为正（got %v）——已过期令牌无需登记，非正 TTL 是配置零值透传的常见形态（#65 同款纪律）", remaining)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hashes[hash] = m.now().Add(remaining)
	return nil
}

// Revoked 判定 token 级撤销（过期条目视为不在）。
func (m *MemRevoker) Revoked(ctx context.Context, hash string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	exp, ok := m.hashes[hash]
	if !ok {
		return false, nil
	}
	return m.now().Before(exp), nil
}

// RevokeUser 设置用户级截断点（单调不回退，取既有值与 at 的较大者——回退
// 会让已判陈旧的令牌复活）。
func (m *MemRevoker) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("authz: RevokeUser 的 userID 不能为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.users[userID]; ok && old.After(at) {
		return nil // 截断点不回退
	}
	m.users[userID] = at
	return nil
}

// RevokedUser 用户级判定：iat 早于截断点（秒截断）即陈旧。
//
// 比较口径单点委托 pwd.TokenStaleBefore（#121 改密陈旧判定的同一份实现——
// 两处各写一份秒截断比较正是 #119/#121 要消灭的漂移形态）。
func (m *MemRevoker) RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	since, ok := m.users[userID]
	if !ok {
		return false, nil
	}
	return pwd.TokenStaleBefore(iat, &since), nil
}

// Sweep 回收 token 级过期条目（用户级截断点不设 TTL，不回收）。
// 读路径本就把过期条目视为不在，Sweep 只影响内存占用，不影响判定语义。
func (m *MemRevoker) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, exp := range m.hashes {
		if !now.Before(exp) {
			delete(m.hashes, k)
		}
	}
}
