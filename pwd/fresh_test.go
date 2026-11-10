package pwd

import (
	"context"
	"testing"
	"time"
)

// TokenStaleBefore：秒截断比较的全部边界（#121 的既定口径：同秒不判陈旧）。
func TestTokenStaleBefore(t *testing.T) {
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	if TokenStaleBefore(base, nil) {
		t.Fatal("无改密记录不得判陈旧")
	}
	for name, tc := range map[string]struct {
		iat       time.Time
		changedAt time.Time
		want      bool
	}{
		"早一秒":              {base.Add(-time.Second), base, true},
		"同秒(iat 无亚秒)":      {base, base.Add(900 * time.Millisecond), false},
		"同秒(两侧亚秒相反)":       {base.Add(900 * time.Millisecond), base.Add(100 * time.Millisecond), false},
		"改密后一秒(新令牌)":       {base.Add(time.Second), base, false},
		"跨日边界":             {base.Add(-24 * time.Hour), base, true},
		"iat 零值(无 iat 令牌)": {time.Time{}, base, true},
	} {
		if got := TokenStaleBefore(tc.iat, &tc.changedAt); got != tc.want {
			t.Fatalf("[%s] TokenStaleBefore = %v, want %v", name, got, tc.want)
		}
	}
}

// ApplyExpiryOnLogin：过期置标 + persist；未过期不动标；fail-closed 语义。
func TestApplyExpiryOnLogin(t *testing.T) {
	ctx := context.Background()
	persistCalls := 0
	persist := func(context.Context) error { persistCalls++; return nil }

	// 未启用过期：no-op。
	must := false
	if err := ApplyExpiryOnLogin(ctx, 0, &must, nil, persist); err != nil {
		t.Fatalf("days=0 应 no-op，got %v", err)
	}
	if must || persistCalls != 0 {
		t.Fatal("days=0 不得置标/落库")
	}

	// 过期：置标 + 落库。
	old := time.Now().AddDate(0, 0, -31)
	must = false
	if err := ApplyExpiryOnLogin(ctx, 30, &must, &old, persist); err != nil {
		t.Fatalf("ApplyExpiryOnLogin() error = %v", err)
	}
	if !must || persistCalls != 1 {
		t.Fatalf("过期必须置标并落库：must=%v persist=%d", must, persistCalls)
	}

	// 未过期：不动标（不清零——可能被其它路径置真）。
	must = true
	fresh := time.Now().AddDate(0, 0, -1)
	if err := ApplyExpiryOnLogin(ctx, 30, &must, &fresh, persist); err != nil {
		t.Fatalf("ApplyExpiryOnLogin() error = %v", err)
	}
	if !must || persistCalls != 1 {
		t.Fatalf("未过期不得清标/落库：must=%v persist=%d", must, persistCalls)
	}

	// 无改密记录：不判过期。
	must = false
	if err := ApplyExpiryOnLogin(ctx, 30, &must, nil, persist); err != nil {
		t.Fatalf("ApplyExpiryOnLogin() error = %v", err)
	}
	if must || persistCalls != 1 {
		t.Fatal("changedAt=nil 不得判过期")
	}

	// persist 失败：原样上抛（fail-closed：标记不落地等于没判定）。
	must = false
	failing := func(context.Context) error { return context.DeadlineExceeded }
	if err := ApplyExpiryOnLogin(ctx, 30, &must, &old, failing); err == nil {
		t.Fatal("persist 失败必须上抛")
	}
	if !must {
		t.Fatal("内存态标记已置位（契约：persist 失败原样上抛，标记保留）")
	}

	// nil mustChange：配置 bug，普通 error。
	if err := ApplyExpiryOnLogin(ctx, 30, nil, &old, persist); err == nil {
		t.Fatal("mustChange=nil 必须报错")
	}
}
