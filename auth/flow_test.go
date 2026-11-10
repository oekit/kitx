package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oekit/kitx/authz"
	"github.com/oekit/kitx/jwt"
	bizerrors "github.com/oekit/pkg/errors"
)

// testClock 假时钟（互斥保护，-race 下并发读安全）。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeRepo UserRepo 测试替身（错误注入 + 调用计数）。
type fakeRepo struct {
	mu        sync.Mutex
	user      *User
	roles     []string
	getErr    error
	roleErr   error
	touchErr  error
	touchCall int
}

func (f *fakeRepo) GetByID(_ context.Context, id string) (*User, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.user == nil || f.user.ID != id {
		return nil, ErrUserNotFound
	}
	// 返回副本（仓储不应被编排层的改写污染）。
	u := &User{ID: f.user.ID, Claims: map[string]any{}}
	for k, v := range f.user.Claims {
		u.Claims[k] = v
	}
	return u, nil
}

func (f *fakeRepo) RoleIDs(_ context.Context, _ string) ([]string, error) {
	if f.roleErr != nil {
		return nil, f.roleErr
	}
	return append([]string(nil), f.roles...), nil
}

func (f *fakeRepo) TouchLogin(_ context.Context, _ string) error {
	f.mu.Lock()
	f.touchCall++
	f.mu.Unlock()
	return f.touchErr
}

// newTestFlow 装配一套 HS256 + 内存状态面的 Flow。
func newTestFlow(t *testing.T, opts ...FlowOption) (*Flow, *authz.MemRevoker, *authz.MemRegistry, *testClock) {
	t.Helper()
	m, err := jwt.NewManagerHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	clk := newTestClock()
	rev := authz.NewMemRevoker(authz.WithRevokerClock(clk.Now))
	reg := authz.NewMemRegistry(rev, authz.WithRegistryClock(clk.Now))
	base := []FlowOption{WithTTL(15*time.Minute, 24*time.Hour), WithClock(clk.Now)}
	f, err := NewFlow(m, reg, rev, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewFlow() error = %v", err)
	}
	return f, rev, reg, clk
}

// NewFlow 构造期 fail-fast（零值透传是最危险的缺省）。
func TestNewFlowValidation(t *testing.T) {
	m, _ := jwt.NewManagerHS256([]byte("0123456789abcdef0123456789abcdef"))
	rev := authz.NewMemRevoker()
	reg := authz.NewMemRegistry(rev)

	for name, tc := range map[string]struct {
		m    *jwt.Manager
		reg  authz.SessionRegistry
		rev  authz.Revoker
		opts []FlowOption
	}{
		"nil manager":       {nil, reg, rev, []FlowOption{WithTTL(time.Minute, time.Hour)}},
		"nil registry":      {m, nil, rev, []FlowOption{WithTTL(time.Minute, time.Hour)}},
		"nil revoker":       {m, reg, nil, []FlowOption{WithTTL(time.Minute, time.Hour)}},
		"TTL 未配置":           {m, reg, rev, nil},
		"TTL 零值":            {m, reg, rev, []FlowOption{WithTTL(0, 0)}},
		"TTL 部分零值":          {m, reg, rev, []FlowOption{WithTTL(time.Minute, 0)}},
		"refresh 短于 access": {m, reg, rev, []FlowOption{WithTTL(time.Hour, time.Minute)}},
	} {
		if _, err := NewFlow(tc.m, tc.reg, tc.rev, tc.opts...); err == nil {
			t.Fatalf("[%s] 必须报错", name)
		}
	}
	if _, err := NewFlow(m, reg, rev, WithTTL(time.Minute, time.Hour)); err != nil {
		t.Fatalf("合法构造 error = %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("WithClock(nil) 必须 panic")
		}
	}()
	_, _ = NewFlow(m, reg, rev, WithTTL(time.Minute, time.Hour), WithClock(nil))
}

// IssuePair 签发尾段：分型/角色/业务声明落位，会话登记（哈希=jti 对账）一次落地。
func TestIssuePair(t *testing.T) {
	ctx := context.Background()
	f, _, reg, clk := newTestFlow(t, WithSignOptions(jwt.WithIssuer("kitx-test")))

	u := &User{
		ID:     "u1",
		Roles:  []string{"admin", "ops"},
		Claims: map[string]any{"tenant": "t1"},
	}
	pair, err := f.IssuePair(ctx, u, SessionMeta{IP: "1.2.3.4", Device: "iphone", UA: "ua-x"})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	if pair.Access == "" || pair.Refresh == "" {
		t.Fatal("双令牌不得为空")
	}
	// 分型 + 会话声明经 jwt 校验面读回。
	ac, err := f.ParseAccess(ctx, pair.Access)
	if err != nil {
		t.Fatalf("ParseAccess() error = %v", err)
	}
	if ac.Subject != "u1" || ac.Issuer != "kitx-test" {
		t.Fatalf("access claims = {iss:%q sub:%q}", ac.Issuer, ac.Subject)
	}
	if ac.Extra["tenant"] != "t1" {
		t.Fatalf("业务声明 = %v", ac.Extra["tenant"])
	}
	roles, ok := ac.Extra["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("角色声明 = %v", ac.Extra["roles"])
	}
	rc, err := f.jwt.ParseTyped(jwt.TokenRefresh, pair.Refresh)
	if err != nil {
		t.Fatalf("ParseTyped(refresh) error = %v", err)
	}
	if ac.ID == rc.ID {
		t.Fatal("access/refresh 的 jti 必须各自独立")
	}
	// 会话登记：哈希口径与 jti 对账。
	s := pair.Session
	if s.UserID != "u1" || s.Device != "iphone" || s.IP != "1.2.3.4" || s.UA != "ua-x" {
		t.Fatalf("会话元数据 = %+v", s)
	}
	if s.AccessHash != authz.TokenHash(pair.Access) || s.RefreshHash != authz.TokenHash(pair.Refresh) {
		t.Fatal("会话哈希必须是 TokenHash 产出口")
	}
	if s.RefreshJTI != rc.ID {
		t.Fatalf("RefreshJTI = %q, want %q", s.RefreshJTI, rc.ID)
	}
	if !s.LoginAt.Equal(clk.Now()) {
		t.Fatalf("LoginAt = %v, want %v", s.LoginAt, clk.Now())
	}
	list, err := reg.ListByUser(ctx, "u1")
	if err != nil || len(list) != 1 || list[0].ID != s.ID {
		t.Fatalf("ListByUser = (%v, %v)", list, err)
	}
}

// 角色声明键防注入面（#71 同款纪律）：Claims 不得占用 rolesClaim。
func TestIssuePairRejectsRolesClaimCollision(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	u := &User{ID: "u1", Claims: map[string]any{"roles": []string{"superadmin"}}}
	if _, err := f.IssuePair(ctx, u, SessionMeta{}); err == nil {
		t.Fatal("Claims 占用角色声明键必须报错")
	}
	if _, err := f.IssuePair(ctx, nil, SessionMeta{}); err == nil {
		t.Fatal("nil 用户必须报错")
	}
	if _, err := f.IssuePair(ctx, &User{}, SessionMeta{}); err == nil {
		t.Fatal("空 ID 用户必须报错")
	}
}

// 登记失败 ⇒ 刚签的双令牌回收（签发与登记一次落地，不放行无主令牌）。
type registerFailRegistry struct {
	authz.SessionRegistry
}

func (r registerFailRegistry) Register(_ context.Context, _ authz.Session, _ time.Duration) error {
	return fmt.Errorf("登记存储故障")
}

// captureRevoker 记录 Revoke 落地次数（黑盒观测回收行为）。
type captureRevoker struct {
	authz.Revoker
	mu   sync.Mutex
	n    int
	ttls []time.Duration
}

func (c *captureRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	c.mu.Lock()
	c.n++
	c.ttls = append(c.ttls, remaining)
	c.mu.Unlock()
	return c.Revoker.Revoke(ctx, hash, remaining)
}

func (c *captureRevoker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestIssuePairRegisterFailureRevokesIssued(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	capRev := &captureRevoker{Revoker: f.revoker}
	f.revoker = capRev
	f.sessions = registerFailRegistry{f.sessions}

	_, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err == nil {
		t.Fatal("登记失败必须报错")
	}
	if !strings.Contains(err.Error(), "登记存储故障") {
		t.Fatalf("错误链必须含登记路原因：%v", err)
	}
	// 无主令牌已回收：恰两路拉黑（access/refresh），TTL 取配置寿命。
	if got := capRev.count(); got != 2 {
		t.Fatalf("回收拉黑次数 = %d, want 2", got)
	}
}

// RotateRefresh 快乐路径：轮换必踢旧会话 + 角色重取 + TouchLogin 尽力而为。
func TestRotateRefreshHappy(t *testing.T) {
	ctx := context.Background()
	f, rev, reg, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}, roles: []string{"viewer"}}

	pair, err := f.IssuePair(ctx, &User{ID: "u1", Roles: []string{"viewer"}}, SessionMeta{Device: "iphone"})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	// 角色变更随轮换生效。
	repo.roles = []string{"admin", "ops"}
	repo.user = &User{ID: "u1", Claims: map[string]any{"tenant": "t1"}}

	rotated, u, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{Device: "mac"})
	if err != nil {
		t.Fatalf("RotateRefresh() error = %v", err)
	}
	if u.ID != "u1" {
		t.Fatalf("轮换产物用户 = %s", u.ID)
	}
	ac, err := f.ParseAccess(ctx, rotated.Access)
	if err != nil {
		t.Fatalf("ParseAccess(新 access) error = %v", err)
	}
	roles, _ := ac.Extra["roles"].([]any)
	if len(roles) != 2 {
		t.Fatalf("轮换后角色 = %v, want [admin ops]", ac.Extra["roles"])
	}
	if ac.Extra["tenant"] != "t1" {
		t.Fatalf("GetByID 的业务声明应随轮换注入：%v", ac.Extra["tenant"])
	}
	// 轮换必踢旧会话：旧双 token 全死，新会话在册。
	if revoked, _ := authz.RevokedToken(ctx, rev, pair.Refresh); !revoked {
		t.Fatal("旧 refresh 必须已拉黑")
	}
	if revoked, _ := authz.RevokedToken(ctx, rev, pair.Access); !revoked {
		t.Fatal("旧 access 必须已拉黑")
	}
	if _, err := reg.GetByRefreshHash(ctx, pair.Session.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
		t.Fatalf("旧会话必须已下线：%v", err)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 1 || list[0].ID != rotated.Session.ID {
		t.Fatalf("新会话必须在册：%v", list)
	}
	if repo.touchCall != 1 {
		t.Fatalf("TouchLogin 调用 = %d, want 1", repo.touchCall)
	}
	// 旧 access 资源侧消费被拒。
	if _, err := f.ParseAccess(ctx, pair.Access); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("旧 access 必须 401：%v", err)
	}
}

// 【钉】旧 refresh 二次使用被拒（#120 防重放）：轮换换出后再用恒 ErrReplayed
// （errors.Is 双判 ErrUnauthorized——401 映射不破）。
func TestRotateRefreshReplayPin(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}}

	pair, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	if _, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{}); err != nil {
		t.Fatalf("首次轮换 error = %v", err)
	}
	// 旧 refresh 第二次使用被拒。
	_, _, err = f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("二次使用必须 ErrReplayed，got %v", err)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("重放错误必须同时可判 ErrUnauthorized（401 映射不破），got %v", err)
	}
	var biz *bizerrors.BizError
	if !errors.As(err, &biz) || biz.HTTPCode != 401 {
		t.Fatalf("重放错误必须是 BizError 401，got %v", err)
	}
}

// 会话不在登记表（被强踢/自然过期）⇒ 按重放拒绝。
func TestRotateRefreshSessionMissing(t *testing.T) {
	ctx := context.Background()
	f, _, reg, clk := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}}

	pair, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	// 被强踢（管理员）。
	if kicked, err := reg.Kick(ctx, pair.Session.ID); err != nil || !kicked {
		t.Fatalf("Kick = (%v, %v)", kicked, err)
	}
	if _, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{}); !errors.Is(err, ErrReplayed) {
		t.Fatalf("被踢会话的 refresh 必须 ErrReplayed，got %v", err)
	}

	// 自然过期（会话 TTL=refresh 寿命，token exp 同步到期——此处只验会话侧口径）。
	pair2, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(25 * time.Hour)
	if _, _, err := f.RotateRefresh(ctx, repo, pair2.Refresh, SessionMeta{}); err == nil {
		t.Fatal("过期 refresh 必须被拒")
	}
}

// 撤销分型：token 级（登出/拉黑）⇒ ErrReplayed；用户级（改密/风控）⇒
// ErrUnauthorized（整体吊销不是重放）。
func TestRotateRefreshRevocationTyping(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepo{user: &User{ID: "u1"}}

	// token 级：登出后再用。
	f1, _, _, _ := newTestFlow(t)
	pair1, _ := f1.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err := f1.Logout(ctx, pair1.Access, pair1.Refresh); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if _, _, err := f1.RotateRefresh(ctx, repo, pair1.Refresh, SessionMeta{}); !errors.Is(err, ErrReplayed) {
		t.Fatalf("登出的 refresh 再用必须 ErrReplayed，got %v", err)
	}

	// 用户级：改密吊销后旧 refresh 归 ErrUnauthorized（iat 注入 1 小时前，
	// 与吊销时刻必然不同秒——秒截断判定的确定性定序，不赌墙钟）。
	f2, _, _, _ := newTestFlow(t, WithSignOptions(jwt.WithIssuedAt(time.Now().Add(-time.Hour))))
	pair2, _ := f2.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err := f2.RevokeUser(ctx, "u1", time.Now()); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	_, _, err := f2.RotateRefresh(ctx, repo, pair2.Refresh, SessionMeta{})
	if !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrReplayed) {
		t.Fatalf("用户级吊销的 refresh 应归 ErrUnauthorized 而非重放，got %v", err)
	}
}

// GetByID 错误分型（#120 不变式）：ErrUserNotFound ⇒ 401；故障 ⇒ 500（不带
// ErrUnauthorized）；(nil, nil) 违约 ⇒ 500。
func TestRotateRefreshErrorTyping(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})

	// 查无此人 ⇒ 401（不泄露存在性）。
	repo := &fakeRepo{getErr: ErrUserNotFound}
	_, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
	if !errors.Is(err, ErrUnauthorized) || !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("查无此人必须 401 且保留 ErrUserNotFound 链，got %v", err)
	}

	// DB 故障 ⇒ 500（错误链保留，不归 401——数据面故障不放大成全站 401）。
	dbErr := fmt.Errorf("db down")
	repo = &fakeRepo{getErr: dbErr}
	_, _, err = f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
	if errors.Is(err, ErrUnauthorized) {
		t.Fatalf("DB 故障不得归 401：%v", err)
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("DB 故障错误链必须保留：%v", err)
	}

	// RoleIDs 故障 ⇒ 500。
	repo = &fakeRepo{user: &User{ID: "u1"}, roleErr: dbErr}
	_, _, err = f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
	if errors.Is(err, ErrUnauthorized) || !errors.Is(err, dbErr) {
		t.Fatalf("RoleIDs 故障分型错：%v", err)
	}

	// (nil, nil) 违约 ⇒ 500。
	_, _, err = f.RotateRefresh(ctx, nilUserRepo{}, pair.Refresh, SessionMeta{})
	if errors.Is(err, ErrUnauthorized) || err == nil {
		t.Fatalf("GetByID 违约必须 500：%v", err)
	}
}

// nilUserRepo 违约替身：GetByID 返回 (nil, nil)（契约要求 ErrUserNotFound）。
type nilUserRepo struct{}

func (nilUserRepo) GetByID(context.Context, string) (*User, error) { return nil, nil }
func (nilUserRepo) RoleIDs(context.Context, string) ([]string, error) {
	return nil, nil
}
func (nilUserRepo) TouchLogin(context.Context, string) error { return nil }

// TouchLogin 尽力而为（#120 不变式）：失败只记日志不阻断轮换。
func TestRotateRefreshTouchLoginBestEffort(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}, touchErr: fmt.Errorf("慢查询超时")}

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if _, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{}); err != nil {
		t.Fatalf("TouchLogin 失败不得阻断轮换：%v", err)
	}
	if repo.touchCall != 1 {
		t.Fatalf("TouchLogin 调用 = %d, want 1", repo.touchCall)
	}
}

// 旧会话下线失败 ⇒ 500（不发新对、不误判重放）。
type kickFailRegistry struct {
	authz.SessionRegistry
}

func (r kickFailRegistry) Kick(_ context.Context, _ string) (bool, error) {
	return false, fmt.Errorf("拉黑存储故障")
}

func TestRotateRefreshKickFailure(t *testing.T) {
	ctx := context.Background()
	f, _, reg, _ := newTestFlow(t)
	f.sessions = kickFailRegistry{reg}
	repo := &fakeRepo{user: &User{ID: "u1"}}

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	_, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
	if err == nil || errors.Is(err, ErrReplayed) {
		t.Fatalf("Kick 故障必须 500 且不误判重放：%v", err)
	}
	// 旧会话保留（可重试），旧 refresh 未被误杀。
	if _, err := reg.GetByRefreshHash(ctx, pair.Session.RefreshHash); err != nil {
		t.Fatalf("旧会话必须保留可重试：%v", err)
	}
}

// 令牌分型防混淆：access 令牌不得走 refresh 轮换。
func TestRotateRefreshRejectsAccessToken(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}}
	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if _, _, err := f.RotateRefresh(ctx, repo, pair.Access, SessionMeta{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("access 走轮换必须 401，got %v", err)
	}
}

// Logout：双 token 撤销 + 会话下线，幂等可重。
func TestLogout(t *testing.T) {
	ctx := context.Background()
	f, _, reg, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{ID: "u1"}}

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err := f.Logout(ctx, pair.Access, pair.Refresh); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	// 双 token 全死：access 401、refresh 重放被拒、会话不在。
	if _, err := f.ParseAccess(ctx, pair.Access); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("登出后 access 必须 401：%v", err)
	}
	if _, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{}); !errors.Is(err, ErrReplayed) {
		t.Fatalf("登出后 refresh 必须被拒：%v", err)
	}
	if _, err := reg.GetByRefreshHash(ctx, pair.Session.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
		t.Fatalf("登出后会话必须下线：%v", err)
	}
	// 幂等：重复登出成功。
	if err := f.Logout(ctx, pair.Access, pair.Refresh); err != nil {
		t.Fatalf("重复登出必须幂等：%v", err)
	}
	// 空入参不误伤。
	if err := f.Logout(ctx, "", ""); err != nil {
		t.Fatalf("空入参登出 = %v", err)
	}
}

// Logout 部分失败：errors.Join 聚合，成功部分照常落地。
type getFailRegistry struct {
	authz.SessionRegistry
}

func (r getFailRegistry) GetByRefreshHash(_ context.Context, _ string) (authz.Session, error) {
	return authz.Session{}, fmt.Errorf("登记表故障")
}

func TestLogoutJoinsErrors(t *testing.T) {
	ctx := context.Background()
	f, rev, reg, _ := newTestFlow(t)
	f.sessions = getFailRegistry{reg}

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	err := f.Logout(ctx, pair.Access, pair.Refresh)
	if err == nil {
		t.Fatal("部分失败必须报错")
	}
	if !strings.Contains(err.Error(), "登记表故障") {
		t.Fatalf("聚合错误必须含各路原因：%v", err)
	}
	// 呈现令牌仍被拉黑（成功部分不回滚）。
	if revoked, _ := authz.RevokedToken(ctx, rev, pair.Access); !revoked {
		t.Fatal("access 拉黑必须落地")
	}
	if revoked, _ := authz.RevokedToken(ctx, rev, pair.Refresh); !revoked {
		t.Fatal("refresh 拉黑必须落地")
	}
}

// RevokeUser（#121 改密吊销钩子）：用户级截断 + 全会话强踢，两路聚合。
func TestRevokeUserHook(t *testing.T) {
	ctx := context.Background()
	f, rev, reg, _ := newTestFlow(t)

	// 两台设备在线。
	pair1, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "iphone"})
	pair2, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "mac"})
	at := time.Now()
	if err := f.RevokeUser(ctx, "u1", at); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	// 在线会话全下线。
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatalf("会话残留 %v", list)
	}
	// 两对令牌全部失效（黑名单 + 陈旧双层都命中）。
	for name, tok := range map[string]string{"pair1-access": pair1.Access, "pair2-access": pair2.Access} {
		if _, err := f.ParseAccess(ctx, tok); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("[%s] 改密后必须 401：%v", name, err)
		}
	}
	if revoked, _ := rev.RevokedUser(ctx, "u1", at.Add(-time.Second)); !revoked {
		t.Fatal("用户级截断点必须落位（存量令牌判陈旧）")
	}
}

// RevokeUser 部分失败：截断与强踢两路 errors.Join 聚合（部分落地也要报全）。
type revokeUserFailRevoker struct {
	authz.Revoker
}

func (r revokeUserFailRevoker) RevokeUser(_ context.Context, _ string, _ time.Time) error {
	return fmt.Errorf("截断存储故障")
}

func TestRevokeUserJoinsErrors(t *testing.T) {
	ctx := context.Background()
	f, rev, reg, _ := newTestFlow(t)
	f.revoker = revokeUserFailRevoker{rev}

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	err := f.RevokeUser(ctx, "u1", time.Now())
	if err == nil {
		t.Fatal("截断失败必须报错")
	}
	if !strings.Contains(err.Error(), "截断存储故障") {
		t.Fatalf("聚合错误必须含截断路原因：%v", err)
	}
	// 强踢路照常落地（部分成功不回滚）。
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatal("强踢路必须照常落地")
	}
	if _, err := f.ParseAccess(ctx, pair.Access); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("已踢令牌必须 401")
	}
	// 包级函数防呆。
	if err := RevokeUser(ctx, nil, reg, "u1", time.Now()); err == nil {
		t.Fatal("nil 依赖必须报错")
	}
	if err := RevokeUser(ctx, rev, reg, "", time.Now()); err == nil {
		t.Fatal("空 userID 必须报错")
	}
}

// ParseAccess：校验 + 双层撤销判定的组合面（#119 与 jwt 校验面可组合）。
func TestParseAccess(t *testing.T) {
	ctx := context.Background()
	f, _, _, _ := newTestFlow(t, WithSignOptions(jwt.WithAudienceClaims("api")))

	pair, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})

	// 共享解析选项生效（aud 钉定）。
	if _, err := f.ParseAccess(ctx, pair.Access, jwt.WithAudience("api")); err != nil {
		t.Fatalf("ParseAccess(aud 命中) error = %v", err)
	}
	if _, err := f.ParseAccess(ctx, pair.Access, jwt.WithAudience("other")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("aud 不命中必须 401：%v", err)
	}
	// 伪造/垃圾令牌 401（保留 jwt 错误链）。
	_, err := f.ParseAccess(ctx, "not-a-token")
	if !errors.Is(err, ErrUnauthorized) || !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("垃圾令牌错误链 = %v", err)
	}
	// refresh 不得当 access 用（分型防混淆）。
	if _, err := f.ParseAccess(ctx, pair.Refresh); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("refresh 走资源侧必须 401：%v", err)
	}
	// 撤销后 401。
	if err := f.Logout(ctx, pair.Access, pair.Refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ParseAccess(ctx, pair.Access); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("撤销后必须 401")
	}
}

// IsRevoked 组合判定（包级锚点）。
func TestIsRevoked(t *testing.T) {
	ctx := context.Background()
	rev := authz.NewMemRevoker()
	token := "tok"
	iat := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	if revoked, err := IsRevoked(ctx, rev, token, "u1", iat); err != nil || revoked {
		t.Fatalf("初始 IsRevoked = (%v, %v), want (false, nil)", revoked, err)
	}
	if err := authz.RevokeToken(ctx, rev, token, time.Hour); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := IsRevoked(ctx, rev, token, "u1", iat); !revoked {
		t.Fatal("token 级命中必须真")
	}
	if revoked, _ := IsRevoked(ctx, rev, "other", "u1", iat); revoked {
		t.Fatal("其它令牌不得误伤")
	}
	if err := rev.RevokeUser(ctx, "u1", iat.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := IsRevoked(ctx, rev, "other", "u1", iat); !revoked {
		t.Fatal("用户级截断命中必须真")
	}
	if revoked, _ := IsRevoked(ctx, rev, "other", "u1", iat.Add(time.Hour)); revoked {
		t.Fatal("截断点之后签发的令牌不得判吊销")
	}
	if _, err := IsRevoked(ctx, nil, token, "u1", iat); err == nil {
		t.Fatal("nil Revoker 必须报错")
	}
}
