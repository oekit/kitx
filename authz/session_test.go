package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// newTestSession 造一条合法登记项（hash 已按 TokenHash 口径）。
func newTestSession(id, user, refreshToken string) Session {
	return Session{
		ID:          id,
		UserID:      user,
		Device:      "iphone",
		IP:          "10.0.0.1",
		UA:          "test-ua",
		RefreshJTI:  "jti-" + id,
		AccessHash:  TokenHash("access-" + id),
		RefreshHash: TokenHash(refreshToken),
		LoginAt:     time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
	}
}

// Register 防呆：必填键、正 ttl、主键/认领键唯一（登记面亦是防重放面）。
func TestMemRegistryRegisterValidation(t *testing.T) {
	ctx := context.Background()
	reg := NewMemRegistry(NewMemRevoker())

	bad := map[string]Session{
		"缺 ID":          {UserID: "u", RefreshHash: "r"},
		"缺 UserID":      {ID: "s", RefreshHash: "r"},
		"缺 RefreshHash": {ID: "s", UserID: "u"},
	}
	for name, s := range bad {
		if err := reg.Register(ctx, s, time.Hour); err == nil {
			t.Fatalf("[%s] 必须报错", name)
		}
	}
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, 0); err == nil {
		t.Fatal("ttl=0 必须报错——零值透传等于登记长生会话")
	}
	if err := reg.Register(ctx, s, -time.Hour); err == nil {
		t.Fatal("负 ttl 必须报错")
	}
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := reg.Register(ctx, s, time.Hour); err == nil {
		t.Fatal("同 ID 重复登记必须报错——登记不可覆盖")
	}
	s2 := newTestSession("s2", "u1", "refresh-1") // 同 refresh 挂不同会话
	if err := reg.Register(ctx, s2, time.Hour); err == nil {
		t.Fatal("同一 refresh 挂第二枚会话必须报错")
	}
	if err := reg.Register(ctx, newTestSession("s3", "u1", "refresh-3"), time.Hour); err != nil {
		t.Fatalf("不同 refresh 登记 error = %v", err)
	}
}

// GetByRefreshHash：轮换认领前置——命中/不在/过期三态。
func TestMemRegistryGetByRefreshHash(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	reg := NewMemRegistry(NewMemRevoker(), WithRegistryClock(clk.Now))
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	got, err := reg.GetByRefreshHash(ctx, s.RefreshHash)
	if err != nil {
		t.Fatalf("GetByRefreshHash() error = %v", err)
	}
	if got.ID != "s1" || got.Device != "iphone" {
		t.Fatalf("GetByRefreshHash = %+v, want s1/iphone", got)
	}
	if _, err := reg.GetByRefreshHash(ctx, "nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("未登记查询 error = %v, want ErrSessionNotFound", err)
	}
	clk.Advance(2 * time.Hour)
	if _, err := reg.GetByRefreshHash(ctx, s.RefreshHash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("过期会话 error = %v, want ErrSessionNotFound", err)
	}
}

// ListByUser：管理端枚举——只列本人、稳定排序（LoginAt→ID）、过期不出现、
// 返回快照。
func TestMemRegistryListByUser(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	reg := NewMemRegistry(NewMemRevoker(), WithRegistryClock(clk.Now))

	s1 := newTestSession("s1", "u1", "refresh-1")
	s2 := newTestSession("s2", "u1", "refresh-2")
	s2.LoginAt = s1.LoginAt.Add(time.Minute) // s2 更晚
	s3 := newTestSession("s3", "u2", "refresh-3")
	for _, s := range []Session{s1, s2, s3} {
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatalf("Register(%s) error = %v", s.ID, err)
		}
	}
	// 短命会话（先过期，验证过滤）。
	s4 := newTestSession("s4", "u1", "refresh-4")
	s4.LoginAt = s1.LoginAt.Add(-time.Minute) // 排序最前但先过期
	if err := reg.Register(ctx, s4, 30*time.Minute); err != nil {
		t.Fatalf("Register(s4) error = %v", err)
	}

	list, err := reg.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}
	if len(list) != 3 || list[0].ID != "s4" || list[1].ID != "s1" || list[2].ID != "s2" {
		t.Fatalf("ListByUser = %v, want [s4 s1 s2]（LoginAt 升序）", ids(list))
	}
	clk.Advance(40 * time.Minute) // s4 过期
	list, err = reg.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}
	if len(list) != 2 || list[0].ID != "s1" {
		t.Fatalf("过期会话不得出现：%v", ids(list))
	}
	if list, _ := reg.ListByUser(ctx, "u2"); len(list) != 1 || list[0].ID != "s3" {
		t.Fatalf("u2 列表 = %v, want [s3]", ids(list))
	}
	if list, _ := reg.ListByUser(ctx, "u-none"); len(list) != 0 {
		t.Fatalf("无会话用户应为空列表，got %v", ids(list))
	}
}

// Kick：双 hash 拉黑 + 删键一次落地；三态契约（true/false/err）。
func TestMemRegistryKick(t *testing.T) {
	ctx := context.Background()
	rev := NewMemRevoker()
	reg := NewMemRegistry(rev)
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if kicked, err := reg.Kick(ctx, "s1"); err != nil || !kicked {
		t.Fatalf("Kick = (%v, %v), want (true, nil)", kicked, err)
	}
	// 双 hash 都已拉黑（强踢必须让令牌失效，不是只删登记）。
	if revoked, _ := rev.Revoked(ctx, s.AccessHash); !revoked {
		t.Fatal("Kick 后 access hash 必须已拉黑")
	}
	if revoked, _ := rev.Revoked(ctx, s.RefreshHash); !revoked {
		t.Fatal("Kick 后 refresh hash 必须已拉黑")
	}
	if _, err := reg.GetByRefreshHash(ctx, s.RefreshHash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Kick 后会话必须已删键，error = %v", err)
	}
	// 幂等：二次 Kick (false, nil)。
	if kicked, err := reg.Kick(ctx, "s1"); err != nil || kicked {
		t.Fatalf("二次 Kick = (%v, %v), want (false, nil)", kicked, err)
	}
}

// 空 hash 字段跳过对应拉黑路（单 token 场景不误伤）。
func TestMemRegistryKickEmptyHashes(t *testing.T) {
	ctx := context.Background()
	reg := NewMemRegistry(NewMemRevoker())
	s := newTestSession("s1", "u1", "refresh-1")
	s.AccessHash = "" // 无 access
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if kicked, err := reg.Kick(ctx, "s1"); err != nil || !kicked {
		t.Fatalf("Kick = (%v, %v), want (true, nil)", kicked, err)
	}
}

// 过期会话 Kick 视为不在（(false, nil)），顺带出清。
func TestMemRegistryKickExpiredSession(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	reg := NewMemRegistry(NewMemRevoker(), WithRegistryClock(clk.Now))
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Minute)
	if kicked, err := reg.Kick(ctx, "s1"); err != nil || kicked {
		t.Fatalf("过期 Kick = (%v, %v), want (false, nil)", kicked, err)
	}
}

// 拉黑落地失败 ⇒ (false, err) 且登记保留（可重试）——「登记没了、令牌还活着」
// 的假下线封死。
type failingRevoker struct {
	inner Revoker
	fail  map[string]bool // hash → 是否失败
}

func (f *failingRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	if f.fail[hash] {
		return fmt.Errorf("存储故障(%s)", hash)
	}
	return f.inner.Revoke(ctx, hash, remaining)
}

func (f *failingRevoker) Revoked(ctx context.Context, hash string) (bool, error) {
	return f.inner.Revoked(ctx, hash)
}

func (f *failingRevoker) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	return f.inner.RevokeUser(ctx, userID, at)
}

func (f *failingRevoker) RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error) {
	return f.inner.RevokedUser(ctx, userID, iat)
}

func TestMemRegistryKickRevokeFailureRetainsEntry(t *testing.T) {
	ctx := context.Background()
	inner := NewMemRevoker()
	rev := &failingRevoker{inner: inner, fail: map[string]bool{}}
	reg := NewMemRegistry(rev)
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatal(err)
	}
	rev.fail[s.RefreshHash] = true
	if kicked, err := reg.Kick(ctx, "s1"); err == nil || kicked {
		t.Fatalf("拉黑失败时 Kick = (%v, %v), want (false, err)", kicked, err)
	}
	// 登记保留：可重试。
	if _, err := reg.GetByRefreshHash(ctx, s.RefreshHash); err != nil {
		t.Fatalf("拉黑失败后登记必须保留，error = %v", err)
	}
	// 修复存储后重试成功。
	delete(rev.fail, s.RefreshHash)
	if kicked, err := reg.Kick(ctx, "s1"); err != nil || !kicked {
		t.Fatalf("重试 Kick = (%v, %v), want (true, nil)", kicked, err)
	}
}

// KickUser：全会话强踢（#119），计数与落地。
func TestMemRegistryKickUser(t *testing.T) {
	ctx := context.Background()
	rev := NewMemRevoker()
	reg := NewMemRegistry(rev)
	hashes := map[string]bool{}
	for _, id := range []string{"s1", "s2", "s3"} {
		s := newTestSession(id, "u1", "refresh-"+id)
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		hashes[s.AccessHash] = true
		hashes[s.RefreshHash] = true
	}
	s4 := newTestSession("s4", "u2", "refresh-s4")
	if err := reg.Register(ctx, s4, time.Hour); err != nil {
		t.Fatal(err)
	}

	n, err := reg.KickUser(ctx, "u1")
	if err != nil {
		t.Fatalf("KickUser() error = %v", err)
	}
	if n != 3 {
		t.Fatalf("KickUser = %d, want 3", n)
	}
	for h := range hashes {
		if revoked, _ := rev.Revoked(ctx, h); !revoked {
			t.Fatalf("hash %s 必须已拉黑", h)
		}
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatalf("u1 会话残留 %v", ids(list))
	}
	if list, _ := reg.ListByUser(ctx, "u2"); len(list) != 1 {
		t.Fatal("u2 不得被波及")
	}
	if n, err := reg.KickUser(ctx, "u1"); err != nil || n != 0 {
		t.Fatalf("二次 KickUser = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := reg.KickUser(ctx, "u-none"); err != nil || n != 0 {
		t.Fatalf("无会话 KickUser = (%d, %v), want (0, nil)", n, err)
	}
}

// KickUser 部分失败：已踢的不回滚，错误聚合上抛（errors.Join）。
func TestMemRegistryKickUserPartialFailure(t *testing.T) {
	ctx := context.Background()
	inner := NewMemRevoker()
	rev := &failingRevoker{inner: inner, fail: map[string]bool{}}
	reg := NewMemRegistry(rev)
	s1 := newTestSession("s1", "u1", "refresh-1")
	s2 := newTestSession("s2", "u1", "refresh-2")
	for _, s := range []Session{s1, s2} {
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	rev.fail[s1.AccessHash] = true

	n, err := reg.KickUser(ctx, "u1")
	if err == nil {
		t.Fatal("部分失败必须报错（errors.Join 聚合）")
	}
	if n != 1 {
		t.Fatalf("KickUser = %d, want 1（失败会话不计数）", n)
	}
	// 失败会话保留可重试，成功会话已落地。
	if _, err := reg.GetByRefreshHash(ctx, s1.RefreshHash); err != nil {
		t.Fatalf("失败会话必须保留，error = %v", err)
	}
	if _, err := reg.GetByRefreshHash(ctx, s2.RefreshHash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("成功会话必须已下线，error = %v", err)
	}
}

// 并发（-race）：两路 Kick 同一会话，**原子认领**保证恰一胜一负（屏障定序：
// 同起点放行后交叉，胜负断言与交错无关）。
func TestMemRegistryKickClaimRace(t *testing.T) {
	ctx := context.Background()
	reg := NewMemRegistry(NewMemRevoker())
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Hour); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan bool, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // 屏障：两路同起点放行
			kicked, err := reg.Kick(ctx, "s1")
			if err != nil {
				t.Errorf("Kick() error = %v", err)
			}
			results <- kicked
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	wins := 0
	for kicked := range results {
		if kicked {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("原子认领必须恰一胜（%d/2）——防重放拍板不靠时序运气", wins)
	}
}

// 并发（-race）：KickUser 与单会话 Kick 竞争同一批会话——认领不重不漏：
// 两路计数之和恒等于会话数（屏障定序，终态断言与交错无关）。
func TestMemRegistryKickUserVsKickRace(t *testing.T) {
	ctx := context.Background()
	reg := NewMemRegistry(NewMemRevoker())
	const total = 4
	for i := 0; i < total; i++ {
		s := newTestSession(fmt.Sprintf("s%d", i), "u1", fmt.Sprintf("refresh-%d", i))
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	var kickedSingle bool
	var kickedUser int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start // 屏障
		n, err := reg.KickUser(ctx, "u1")
		if err != nil {
			t.Errorf("KickUser() error = %v", err)
		}
		kickedUser = n
	}()
	go func() {
		defer wg.Done()
		<-start // 屏障
		kicked, err := reg.Kick(ctx, "s0")
		if err != nil {
			t.Errorf("Kick() error = %v", err)
		}
		kickedSingle = kicked
	}()
	close(start)
	wg.Wait()

	single := 0
	if kickedSingle {
		single = 1
	}
	if kickedUser+single != total {
		t.Fatalf("认领不重不漏：KickUser(%d) + Kick(%d) = %d, want %d",
			kickedUser, single, kickedUser+single, total)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatalf("终态会话残留 %v", ids(list))
	}
}

// Sweep：过期登记回收（读判本就视为不在）。
func TestMemRegistrySweep(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	reg := NewMemRegistry(NewMemRevoker(), WithRegistryClock(clk.Now))
	s := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Minute)
	reg.Sweep()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if len(reg.byID) != 0 || len(reg.byRefresh) != 0 || len(reg.byUser) != 0 {
		t.Fatalf("Sweep 后残留：byID=%d byRefresh=%d byUser=%d",
			len(reg.byID), len(reg.byRefresh), len(reg.byUser))
	}
}

// 构造防呆：nil Revoker panic（无拉黑的强踢是假强踢）；nil 时钟 panic。
func TestMemRegistryConstructionPanics(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("NewMemRegistry(nil) 必须 panic")
			}
		}()
		_ = NewMemRegistry(nil)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("WithRegistryClock(nil) 必须 panic")
			}
		}()
		_ = NewMemRegistry(NewMemRevoker(), WithRegistryClock(nil))
	}()
}

// ids 提取会话 ID 列表（断言可读性）。
func ids(list []Session) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}
