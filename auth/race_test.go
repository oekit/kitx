package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oekit/kitx/authz"
)

// gateRegistry 会话注册表屏障替身：GetByRefreshHash 命中即「到场签到」并阻塞，
// 待全部竞争方到场后统一放行——把「双方都过了校验、同时进入认领」这一竞态
// 窗口**定序**成必然事件，胜负断言不再靠 sleep 碰运气。
type gateRegistry struct {
	authz.SessionRegistry
	arrived chan struct{}
	release chan struct{}
}

func (g *gateRegistry) GetByRefreshHash(ctx context.Context, hash string) (authz.Session, error) {
	s, err := g.SessionRegistry.GetByRefreshHash(ctx, hash)
	if err == nil {
		g.arrived <- struct{}{} // 签到
		<-g.release             // 等全部到场
	}
	return s, err
}

// 【钉】轮换竞态（#120 防重放）：两个并发 RotateRefresh 携同一 refresh，
// 屏障定序保证双双通过校验后同时进入 Kick 认领——恰一胜一负，败方
// ErrReplayed。旧 refresh 的**单次使用**由原子认领保证，不靠时序运气。
func TestRotateRefreshClaimRace(t *testing.T) {
	ctx := context.Background()
	f, _, reg, _ := newTestFlow(t)
	gate := &gateRegistry{
		SessionRegistry: reg,
		arrived:         make(chan struct{}, 2),
		release:         make(chan struct{}),
	}
	f.sessions = gate
	repo := &fakeRepo{user: &User{ID: "u1"}}

	pair, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{})
			errs <- err
		}()
	}
	// 屏障定序：两路都完成校验、停在认领前，再同时放行。
	<-gate.arrived
	<-gate.arrived
	close(gate.release)
	wg.Wait()
	close(errs)

	wins, replays := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrReplayed):
			replays++
		default:
			t.Fatalf("意外错误形态：%v", err)
		}
	}
	if wins != 1 || replays != 1 {
		t.Fatalf("恰一胜一负（wins=%d replays=%d）——防重放拍板靠原子认领", wins, replays)
	}
	// 终态：胜者的新会话在册，旧会话已下线。
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 1 {
		t.Fatalf("终态会话 = %d, want 1（胜者的新会话）", len(list))
	}
	if _, err := reg.GetByRefreshHash(ctx, pair.Session.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
		t.Fatalf("旧会话必须已下线：%v", err)
	}
}

// 【钉】强踢竞态（#119）：改密吊销（KickUser 全会话强踢）与单会话下线并发，
// 认领不重不漏——两路计数之和恒等于会话数，终态全下线。
func TestRevokeUserVsKickRace(t *testing.T) {
	ctx := context.Background()
	f, _, reg, _ := newTestFlow(t)

	const n = 3
	pairs := make([]*TokenPair, 0, n)
	for i := 0; i < n; i++ {
		p, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: string(rune('a' + i))})
		if err != nil {
			t.Fatalf("IssuePair(%d) error = %v", i, err)
		}
		pairs = append(pairs, p)
	}

	start := make(chan struct{})
	var revokeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start // 屏障：同起点放行
		revokeErr = f.RevokeUser(ctx, "u1", time.Now())
	}()
	go func() {
		defer wg.Done()
		<-start // 屏障
		// 单会话下线与全会话强踢竞争同一会话（胜负不定，终态不变式在下面钉死；
		// 计数口径的「不重不漏」断言见 authz 侧 TestMemRegistryKickUserVsKickRace）。
		if _, err := reg.Kick(ctx, pairs[0].Session.ID); err != nil {
			t.Errorf("Kick() error = %v", err)
		}
	}()
	close(start)
	wg.Wait()

	if revokeErr != nil {
		t.Fatalf("RevokeUser() error = %v", revokeErr)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatalf("终态会话残留 %d", len(list))
	}
	// 全部令牌失效（无论谁踢的）。
	for i, p := range pairs {
		if _, err := f.ParseAccess(ctx, p.Access); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("pair[%d] 必须 401：%v", i, err)
		}
	}
}
