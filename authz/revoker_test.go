package authz

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock 假时钟（互斥保护，-race 下并发读安全）。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TokenHash 是键空间唯一产出口：sha256hex 小写，已知向量钉死口径。
func TestTokenHashKnownVector(t *testing.T) {
	// sha256("abc") 的权威向量（FIPS 180-2）。
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := TokenHash("abc"); got != want {
		t.Fatalf("TokenHash(abc) = %s, want %s", got, want)
	}
	if got := TokenHash("abc"); got != want {
		t.Fatalf("TokenHash 不稳定：%s != %s", got, want)
	}
	if TokenHash("abd") == want {
		t.Fatal("不同令牌不得同哈希")
	}
	if len(TokenHash("x")) != 64 {
		t.Fatalf("TokenHash 长度 = %d, want 64（sha256hex）", len(TokenHash("x")))
	}
	if got := TokenHash("ABC"); strings.ToLower(got) != got {
		t.Fatal("TokenHash 必须小写 hex")
	}
}

// token 级：登记即判吊销，未登记不误伤。
func TestMemRevokerTokenLevel(t *testing.T) {
	ctx := context.Background()
	r := NewMemRevoker()
	if revoked, err := r.Revoked(ctx, "h1"); err != nil || revoked {
		t.Fatalf("未登记条目 Revoked = (%v, %v), want (false, nil)", revoked, err)
	}
	if err := r.Revoke(ctx, "h1", time.Hour); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revoked, err := r.Revoked(ctx, "h1"); err != nil || !revoked {
		t.Fatalf("已登记条目 Revoked = (%v, %v), want (true, nil)", revoked, err)
	}
	if revoked, _ := r.Revoked(ctx, "h2"); revoked {
		t.Fatal("h2 不得被 h1 的登记波及")
	}
}

// TTL 生命周期：条目 TTL=剩余寿命，到点即出清（过期令牌本就被 exp 拒绝）。
func TestMemRevokerTTLExpiry(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	r := NewMemRevoker(WithRevokerClock(clk.Now))
	if err := r.Revoke(ctx, "h1", time.Hour); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	clk.Advance(59 * time.Minute)
	if revoked, _ := r.Revoked(ctx, "h1"); !revoked {
		t.Fatal("TTL 内必须仍判吊销")
	}
	clk.Advance(time.Minute) // 恰到失效时刻
	if revoked, _ := r.Revoked(ctx, "h1"); revoked {
		t.Fatal("TTL 到点必须判过期（条目出清）")
	}
}

// Revoke 入参防呆：空键/非正 remaining 拒绝（#65 同款零值透传纪律）。
func TestMemRevokerRevokeRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	r := NewMemRevoker()
	if err := r.Revoke(ctx, "", time.Hour); err == nil {
		t.Fatal("空 hash 必须报错——键必须出自 TokenHash")
	}
	for _, d := range []time.Duration{0, -time.Minute} {
		if err := r.Revoke(ctx, "h", d); err == nil {
			t.Fatalf("remaining=%v 必须报错", d)
		}
	}
	if err := r.RevokeUser(ctx, "", time.Now()); err == nil {
		t.Fatal("空 userID 必须报错")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Revoke(canceled, "h", time.Hour); err == nil {
		t.Fatal("已取消 ctx 必须报错")
	}
}

// 用户级：截断点判定 + 秒截断边界（同秒不判陈旧，pwd.TokenStaleBefore 同口径）。
func TestMemRevokerUserCutoff(t *testing.T) {
	ctx := context.Background()
	r := NewMemRevoker()
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	if revoked, err := r.RevokedUser(ctx, "u1", base); err != nil || revoked {
		t.Fatalf("无截断点 RevokedUser = (%v, %v), want (false, nil)", revoked, err)
	}
	if err := r.RevokeUser(ctx, "u1", base.Add(time.Second)); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	for name, tc := range map[string]struct {
		iat  time.Time
		want bool
	}{
		"早一秒(整)":        {base, true},
		"早一秒(亚秒)":       {base.Add(900 * time.Millisecond), true},
		"同秒新签(改密后)":     {base.Add(time.Second + 900*time.Millisecond), false},
		"截断点后一秒":        {base.Add(2 * time.Second), false},
		"零值 iat(无 iat)": {time.Time{}, true},
	} {
		if got, err := r.RevokedUser(ctx, "u1", tc.iat); err != nil || got != tc.want {
			t.Fatalf("[%s] RevokedUser = (%v, %v), want (%v, nil)", name, got, err, tc.want)
		}
	}
	if revoked, _ := r.RevokedUser(ctx, "u2", base); revoked {
		t.Fatal("其它用户不得被 u1 的截断点波及")
	}
}

// 截断点单调不回退：更早的 at 不得把已判陈旧的令牌放活（fail-open 封死）。
func TestMemRevokerCutoffMonotonic(t *testing.T) {
	ctx := context.Background()
	r := NewMemRevoker()
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if err := r.RevokeUser(ctx, "u1", base.Add(time.Hour)); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	if err := r.RevokeUser(ctx, "u1", base); err != nil {
		t.Fatalf("RevokeUser(更早) error = %v", err)
	}
	if revoked, _ := r.RevokedUser(ctx, "u1", base.Add(30*time.Minute)); !revoked {
		t.Fatal("截断点回退后旧令牌复活——必须单调不回退")
	}
}

// 原始令牌串助手（TokenHash 单点的消费面）。
func TestMemRevokerTokenHelpers(t *testing.T) {
	ctx := context.Background()
	r := NewMemRevoker()
	token := "header.payload.sig"
	if err := RevokeToken(ctx, r, token, time.Hour); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}
	if revoked, err := RevokedToken(ctx, r, token); err != nil || !revoked {
		t.Fatalf("RevokedToken = (%v, %v), want (true, nil)", revoked, err)
	}
	if revoked, _ := r.Revoked(ctx, TokenHash(token)); !revoked {
		t.Fatal("助手与 hash 级入口必须同一键空间")
	}
}

// Sweep 只影响内存占用（过期条目读判本就视为不在），用户级截断点不回收。
func TestMemRevokerSweep(t *testing.T) {
	ctx := context.Background()
	clk := newFakeClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	r := NewMemRevoker(WithRevokerClock(clk.Now))
	if err := r.Revoke(ctx, "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeUser(ctx, "u1", clk.Now()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	r.Sweep()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hashes) != 0 {
		t.Fatalf("Sweep 后过期条目残留 %d 条", len(r.hashes))
	}
	if len(r.users) != 1 {
		t.Fatalf("用户级截断点不应被 Sweep 回收，剩 %d 条", len(r.users))
	}
}

// 并发（-race）：批量 Revoke/RevokeUser/Revoked 交叉，终态确定——全部登记
// 生效、截断点取并发设置的最大值（屏障定序：同起点放行后交叉，终态断言与
// 交错无关）。
func TestMemRevokerConcurrency(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	r := NewMemRevoker()

	const n = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 屏障：全部就绪后同起点放行
			hash := TokenHash(string(rune('a'+i%26)) + string(rune('0'+i/26)))
			if err := r.Revoke(ctx, hash, time.Hour); err != nil {
				t.Errorf("Revoke(%d) error = %v", i, err)
			}
			at := base.Add(time.Duration(i) * time.Second)
			if err := r.RevokeUser(ctx, "u", at); err != nil {
				t.Errorf("RevokeUser(%d) error = %v", i, err)
			}
			if revoked, err := r.Revoked(ctx, hash); err != nil || !revoked {
				t.Errorf("Revoked(%d) = (%v, %v), want (true, nil)", i, revoked, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// 截断点必须是并发设置的最大值（单调性在竞态下的终态断言）。
	if revoked, err := r.RevokedUser(ctx, "u", base.Add((n-1)*time.Second).Add(-time.Second)); err != nil || !revoked {
		t.Fatalf("终态截断点应为最大 at：RevokedUser = (%v, %v), want (true, nil)", revoked, err)
	}
	if revoked, _ := r.RevokedUser(ctx, "u", base.Add((n-1)*time.Second).Add(time.Second)); revoked {
		t.Fatal("终态截断点不得超出最大 at")
	}
}

// 时钟注入防呆（WithNow（#64）同款纪律）。
func TestMemRevokerClockOptionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithRevokerClock(nil) 必须 panic")
		}
	}()
	_ = NewMemRevoker(WithRevokerClock(nil))
}
