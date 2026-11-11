package authz

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// gateRevoker 只把**首次** Revoke 调用卡在闸门上（其余直通）：复现 Kick 的
// 解锁-重锁窗口——A 的拉黑调用被卡住时，A 已解锁，B/C 可完整交错。CAS 先置位
// 再阻塞：后续调用（B 的拉黑）直通，不会跟着卡死（sync.Once 会）。
type gateRevoker struct {
	inner   Revoker
	arrive  chan struct{} // 首次 Revoke 到达闸门
	release chan struct{} // 关闭后放行
	passed  atomic.Bool   // 首次调用已占住闸门
}

func (g *gateRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	if g.passed.CompareAndSwap(false, true) {
		g.arrive <- struct{}{}
		<-g.release
	}
	return g.inner.Revoke(ctx, hash, remaining)
}

func (g *gateRevoker) Revoked(ctx context.Context, hash string) (bool, error) {
	return g.inner.Revoked(ctx, hash)
}

func (g *gateRevoker) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	return g.inner.RevokeUser(ctx, userID, at)
}

func (g *gateRevoker) RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error) {
	return g.inner.RevokedUser(ctx, userID, iat)
}

// #136 回归（-race）：Kick 解锁-重锁窗口的 ABA——重锁后复检必须按登记项
// **身份**（*regEntry 指针）而非存在性。
//
// 交错编排（闸门把 A 的首次拉黑卡在锁外，其余步骤主线程定序）：
//
//	A.Kick(s1)：持锁读到 E1 → 解锁 → 拉黑 access（卡闸）
//	B.Kick(s1)：完整踢掉 E1（双 hash 拉黑 + 删键，true）
//	C.Register(s1)：同 ID 重建会话（RefreshHash 不同，新 *regEntry）
//	A 放行 → 重锁：byID[s1] 命中的是 C 的新登记
//
// 修复语义：A 复检指针 ≠ 自己读到的 entry ⇒ 判败方返回 (false, nil)，C 的
// 重建会话原地不动。若只判存在性（修复前），A 会把 C 的会话连同双索引静默
// 误删还报 (true, nil)——下游自定义固定 ID 会话 / 对拍 Redis 实现时窗口真实
// 存在（库内随机 32 hex 会话 ID 概率≈0 不代表接口契约安全）。
func TestMemRegistryKickABARebuiltSameID(t *testing.T) {
	ctx := context.Background()
	rev := &gateRevoker{
		inner:   NewMemRevoker(),
		arrive:  make(chan struct{}),
		release: make(chan struct{}),
	}
	reg := NewMemRegistry(rev)

	e1 := newTestSession("s1", "u1", "refresh-1")
	if err := reg.Register(ctx, e1, time.Hour); err != nil {
		t.Fatal(err)
	}

	// A：Kick 进入拉黑段并卡闸（解锁-重锁窗口开启）。
	aDone := make(chan bool, 1)
	go func() {
		kicked, err := reg.Kick(ctx, "s1")
		if err != nil {
			t.Errorf("A.Kick() error = %v", err)
		}
		aDone <- kicked
	}()
	<-rev.arrive

	// B：完整踢掉 E1。
	if kicked, err := reg.Kick(ctx, "s1"); err != nil || !kicked {
		t.Fatalf("B.Kick() = (%v, %v), want (true, nil)", kicked, err)
	}

	// C：同 ID 重建（RefreshHash 不同——重建会话是独立登记）。
	e2 := newTestSession("s1", "u1", "refresh-2")
	if err := reg.Register(ctx, e2, time.Hour); err != nil {
		t.Fatalf("C.Register(同 ID 重建) error = %v", err)
	}

	// 放行 A：拉黑落地 → 重锁复检。
	close(rev.release)
	if kicked := <-aDone; kicked {
		t.Fatal("A.Kick() 必须判败方返回 false——重锁后命中的是重建会话，不是自己读到的登记（#136 ABA）")
	}

	// C 的重建会话原地不动（修复前会连同双索引一起被 A 静默误删）。
	got, err := reg.GetByRefreshHash(ctx, TokenHash("refresh-2"))
	if err != nil {
		t.Fatalf("重建会话被误删: %v（#136：复检只判存在性时 A 会误删 C 的登记）", err)
	}
	if got.ID != "s1" || got.RefreshHash != TokenHash("refresh-2") {
		t.Fatalf("重建会话内容漂移：got %+v", got)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("u1 会话终态 = %v, want 恰一条重建会话 s1", ids(list))
	}
	// 旧会话的 refresh 已拉黑（B 落地过）。
	if hit, err := rev.inner.Revoked(ctx, TokenHash("refresh-1")); err != nil || !hit {
		t.Fatalf("旧会话 refresh-1 必须已拉黑（hit=%v err=%v）", hit, err)
	}
}
