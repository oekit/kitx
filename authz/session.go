package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// ErrSessionNotFound 表示会话不在登记表（未登记 / 已过期 / 已下线）。
var ErrSessionNotFound = errors.New("authz: 会话不存在")

// Session 是一条在线会话登记项（设备/会话维度，#119）。
//
// 登记表回答「某用户在哪些设备在线」（ListByUser → Device/IP/UA/LoginAt），
// 强踢回答「如何把他踢下线」（Kick/KickUser → 双 hash 拉黑 + 删键）。
//
// 哈希字段（AccessHash/RefreshHash）是 TokenHash 产出口：登记期由编排层
// （kitx/auth）算好写入，拉黑期由注册表直接消费——原始令牌串不进登记表
// （存储面不落明文凭据）。
type Session struct {
	// ID 会话 ID（登记表主键，编排层生成；同一次登录一对令牌一枚会话 ID）。
	ID string
	// UserID 会话归属用户。
	UserID string
	// Device 设备标识（自由文本，管理端枚举/按设备辨识用；可空）。
	Device string
	// IP 登录来源 IP（审计留痕；可空）。
	IP string
	// UA 登录客户端 UA（审计留痕；可空）。
	UA string
	// RefreshJTI 会话对应的 refresh 令牌 jti（管理端展示与对账；可空）。
	RefreshJTI string
	// AccessHash access 令牌的 TokenHash（强踢拉黑口径；可空——空则 Kick 跳过该路）。
	AccessHash string
	// RefreshHash refresh 令牌的 TokenHash（轮换认领键；必填）。
	RefreshHash string
	// LoginAt 登录/换发时刻。
	LoginAt time.Time
}

// SessionRegistry 在线会话注册表存储面（#119）：接口化存储。
//
// 生命周期契约：登记 TTL 是 refresh 令牌的**剩余寿命**（编排层以 ttlRefresh
// 登记）——会话过期即两令牌都已自然失效（编排层保证 ttlRefresh ≥ ttlAccess，
// 登记 TTL 是两令牌寿命的上界）。持久实现（Redis）按键前缀可配 + TTL=登记
// 寿命落地即可。
//
// 强踢契约（Kick）：**双 hash 拉黑 + 删键**一次落地——只删登记不拉黑等于假
// 强踢（令牌还活着），只拉黑不删键会让会话继续被枚举为在线。拉黑落地失败时
// 登记必须保留（可重试），见 Kick 的三态返回。
type SessionRegistry interface {
	// Register 登记会话（ttl=refresh 剩余寿命，必须为正）。
	// ID 已被未过期会话占用、或 RefreshHash 已挂在另一会话上 ⇒ 报错
	// （同一 refresh 不得挂两枚会话——登记面本身也是防重放面）。
	Register(ctx context.Context, s Session, ttl time.Duration) error
	// GetByRefreshHash 按 refresh 哈希查会话（refresh 轮换的认领前置）。
	// 不在（未登记/已过期/已下线）⇒ ErrSessionNotFound。
	GetByRefreshHash(ctx context.Context, refreshHash string) (Session, error)
	// ListByUser 枚举某用户的在线会话（管理端；按 LoginAt、ID 稳定排序，
	// 过期会话不出现）。返回值是快照副本，改写不影响登记表。
	ListByUser(ctx context.Context, userID string) ([]Session, error)
	// Kick 强踢单会话：双 hash 拉黑 + 删键，**原子认领**。三态契约：
	//   - (true, nil)：完整下线（拉黑与删键都已落地）；
	//   - (false, nil)：登记不存在（幂等强踢的常态 / 轮换竞态的败方）；
	//   - (false, err)：拉黑落地失败，登记**保留**（可重试）。
	//
	// 原子认领（claim）是 refresh 轮换防重放的拍板点：并发轮换/强踢竞争同一
	// 会话时恰有一个调用拿到 true，其余按败方拒绝——「旧 refresh 二次使用被拒」
	// 不靠时序运气。
	Kick(ctx context.Context, id string) (bool, error)
	// KickUser 强踢某用户全部在线会话（#119 强踢全会话；改密吊销钩子的落地
	// 一半）。返回完整下线的会话数；部分失败时已踢的不回滚，错误聚合上抛
	// （errors.Join）。
	KickUser(ctx context.Context, userID string) (int, error)
}

// regEntry 登记项（会话 + 到期时刻）。
type regEntry struct {
	session   Session
	expiresAt time.Time
}

// MemRegistry 是 SessionRegistry 的内存实现：并发安全（mutex 保护），
// 与 MemRevoker 配对使用（Kick 的双 hash 拉黑经构造注入的 Revoker 落地）。
//
// 定位与 MemRevoker 一致：单实例进程内形态 + 契约测试替身。不启动后台
// goroutine——过期会话读判即视为不在，Sweep 可手动回收。
type MemRegistry struct {
	mu        sync.RWMutex
	rev       Revoker
	now       func() time.Time
	byID      map[string]*regEntry           // 会话 ID → 登记项
	byRefresh map[string]string              // RefreshHash → 会话 ID
	byUser    map[string]map[string]struct{} // userID → 会话 ID 集合
}

// MemRegistryOption 是 NewMemRegistry 的函数选项。
type MemRegistryOption func(*MemRegistry)

// WithRegistryClock 注入 MemRegistry 时钟（f 为 nil 直接 panic，WithRevokerClock
// 同款纪律）。
func WithRegistryClock(f func() time.Time) MemRegistryOption {
	return func(m *MemRegistry) {
		if f == nil {
			panic("authz: WithRegistryClock 的时钟函数不能为 nil——静默回落 time.Now() 会让时钟无声漂移")
		}
		m.now = f
	}
}

// NewMemRegistry 构造内存会话注册表。rev 是 Kick/KickUser 双 hash 拉黑的
// 落地口，必须非 nil——强踢无拉黑等于假强踢（#65 同款零值透传纪律，构造期
// fail-fast panic）。
func NewMemRegistry(rev Revoker, opts ...MemRegistryOption) *MemRegistry {
	if rev == nil {
		panic("authz: NewMemRegistry 需要非 nil Revoker——Kick/KickUser 的双 hash 拉黑经它落地，无拉黑的强踢是假强踢")
	}
	m := &MemRegistry{
		rev:       rev,
		now:       time.Now,
		byID:      make(map[string]*regEntry),
		byRefresh: make(map[string]string),
		byUser:    make(map[string]map[string]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Register 登记会话（契约见 SessionRegistry）。
func (m *MemRegistry) Register(ctx context.Context, s Session, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ID == "" || s.UserID == "" || s.RefreshHash == "" {
		return fmt.Errorf("authz: Register 的 ID/UserID/RefreshHash 必填（ID=登记主键、RefreshHash=轮换认领键）")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: Register 的 ttl 必须为正（got %v）——ttl 是 refresh 剩余寿命，零值透传等于登记长生会话（#65 同款纪律）", ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweepLocked(now)
	if old, ok := m.byID[s.ID]; ok && now.Before(old.expiresAt) {
		return fmt.Errorf("authz: 会话 ID %q 已登记——登记不可覆盖，先 Kick 再登记", s.ID)
	}
	if owner, ok := m.byRefresh[s.RefreshHash]; ok && owner != s.ID {
		if old, ok2 := m.byID[owner]; ok2 && now.Before(old.expiresAt) {
			return fmt.Errorf("authz: RefreshHash 已挂在会话 %q 上——同一 refresh 不得挂两枚会话（登记面亦是防重放面）", owner)
		}
	}
	m.removeLocked(s.ID)
	m.byID[s.ID] = &regEntry{session: s, expiresAt: now.Add(ttl)}
	m.byRefresh[s.RefreshHash] = s.ID
	if m.byUser[s.UserID] == nil {
		m.byUser[s.UserID] = make(map[string]struct{})
	}
	m.byUser[s.UserID][s.ID] = struct{}{}
	return nil
}

// GetByRefreshHash 按 refresh 哈希查会话（契约见 SessionRegistry）。
func (m *MemRegistry) GetByRefreshHash(ctx context.Context, refreshHash string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	id, ok := m.byRefresh[refreshHash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	entry, ok := m.byID[id]
	if !ok || !now.Before(entry.expiresAt) {
		// 索引残留/过期：就地出清，语义等同不在。
		delete(m.byRefresh, refreshHash)
		return Session{}, ErrSessionNotFound
	}
	return entry.session, nil
}

// ListByUser 枚举某用户的在线会话（契约见 SessionRegistry）。
func (m *MemRegistry) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]Session, 0, len(m.byUser[userID]))
	for id := range m.byUser[userID] {
		entry, ok := m.byID[id]
		if !ok || !now.Before(entry.expiresAt) {
			continue
		}
		out = append(out, entry.session)
	}
	// 稳定排序（LoginAt → ID）：管理端枚举顺序确定，不随 map 遍历序漂。
	slices.SortFunc(out, func(a, b Session) int {
		if c := a.LoginAt.Compare(b.LoginAt); c != 0 {
			return c
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out, nil
}

// Kick 强踢单会话（契约见 SessionRegistry 的三态返回）。
//
// 时序：先拉黑（登记保留、失败可重试）后原子删键（claim 拍板）——拉黑失败
// 时不动登记，避免「登记没了、令牌还活着」的假下线。
func (m *MemRegistry) Kick(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	entry, ok := m.byID[id]
	if !ok || !m.now().Before(entry.expiresAt) {
		m.removeLocked(id) // 过期/残留顺带出清
		m.mu.Unlock()
		return false, nil
	}
	s := entry.session
	remaining := entry.expiresAt.Sub(m.now())
	m.mu.Unlock()

	var errs []error
	if s.AccessHash != "" {
		if err := m.rev.Revoke(ctx, s.AccessHash, remaining); err != nil {
			errs = append(errs, fmt.Errorf("拉黑 access: %w", err))
		}
	}
	if s.RefreshHash != "" {
		if err := m.rev.Revoke(ctx, s.RefreshHash, remaining); err != nil {
			errs = append(errs, fmt.Errorf("拉黑 refresh: %w", err))
		}
	}
	if len(errs) > 0 {
		return false, errors.Join(errs...) // errors.Join：双路拉黑失败聚合报全
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return false, nil // 竞态败方：已被其它 Kick/KickUser 认领
	}
	m.removeLocked(id)
	return true, nil
}

// KickUser 强踢某用户全部在线会话（契约见 SessionRegistry）。
func (m *MemRegistry) KickUser(ctx context.Context, userID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	now := m.now()
	ids := make([]string, 0, len(m.byUser[userID]))
	for id := range m.byUser[userID] {
		entry, ok := m.byID[id]
		if !ok || !now.Before(entry.expiresAt) {
			continue
		}
		ids = append(ids, id)
	}
	m.mu.Unlock()

	count := 0
	var errs []error
	for _, id := range ids {
		kicked, err := m.Kick(ctx, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if kicked {
			count++
		}
	}
	return count, errors.Join(errs...)
}

// Sweep 回收过期登记（读路径已把过期会话视为不在，Sweep 只影响内存占用）。
func (m *MemRegistry) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(m.now())
}

// sweepLocked 出清过期登记（调用方持锁）。
func (m *MemRegistry) sweepLocked(now time.Time) {
	for id, entry := range m.byID {
		if !now.Before(entry.expiresAt) {
			m.removeLocked(id)
		}
	}
}

// removeLocked 摘除一条登记（主键 + 双索引，调用方持锁）。
func (m *MemRegistry) removeLocked(id string) {
	entry, ok := m.byID[id]
	if !ok {
		return
	}
	delete(m.byID, id)
	if owner, ok := m.byRefresh[entry.session.RefreshHash]; ok && owner == id {
		delete(m.byRefresh, entry.session.RefreshHash)
	}
	if set, ok := m.byUser[entry.session.UserID]; ok {
		delete(set, id)
		if len(set) == 0 {
			delete(m.byUser, entry.session.UserID)
		}
	}
}
