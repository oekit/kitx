package pwd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 直等比对器（测试替身：真实形态是 bcrypt.CompareHashAndPassword 包装）。
func plainMatch(stored, candidate string) (bool, error) { return stored == candidate, nil }

// fail-closed 契约（#121 核心取舍）：Fetch/Match 出错 ≠ 放行。
func TestHistoryCheckFailClosed(t *testing.T) {
	ctx := context.Background()

	fetchErr := HistoryCheck{
		Count: 3,
		Fetch: func(context.Context, string, int) ([]string, error) {
			return nil, fmt.Errorf("db down")
		},
		Match: plainMatch,
	}
	err := fetchErr.Check(ctx, "u1", "new-password")
	if err == nil {
		t.Fatal("历史查询失败绝不能放行（fail-closed）")
	}
	if IsViolation(err) {
		t.Fatalf("查询故障是 500 类，不得归 Violation(400)：%v", err)
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("错误应点明 fail-closed 语义：%v", err)
	}

	matchErr := HistoryCheck{
		Count: 3,
		Fetch: func(context.Context, string, int) ([]string, error) { return []string{"bad-hash"}, nil },
		Match: func(stored, candidate string) (bool, error) { return false, fmt.Errorf("hash format") },
	}
	if err := matchErr.Check(ctx, "u1", "new-password"); err == nil || IsViolation(err) {
		t.Fatalf("比对失败必须 fail-closed 上抛，got %v", err)
	}
}

// 命中历史 ⇒ Violation(KindHistory, 400)；新密码放行；count 透传。
func TestHistoryCheckReuse(t *testing.T) {
	ctx := context.Background()
	gotCount := 0
	h := HistoryCheck{
		Count: 5,
		Fetch: func(_ context.Context, userID string, count int) ([]string, error) {
			if userID != "u1" {
				t.Errorf("userID = %s, want u1", userID)
			}
			gotCount = count
			return []string{"old-a", "old-b", "secret-old"}, nil
		},
		Match: plainMatch,
	}
	if err := h.Check(ctx, "u1", "secret-old"); err == nil {
		t.Fatal("与历史重复必须违规")
	} else {
		var v *Violation
		if !errors.As(err, &v) || v.Kind != KindHistory {
			t.Fatalf("违规 = %v, want *Violation(KindHistory)", err)
		}
		var want = "新密码与近期使用过的密码重复，请换一个"
		if v.Message != want {
			t.Fatalf("文案 = %q, want %q", v.Message, want)
		}
	}
	if err := h.Check(ctx, "u1", "brand-new"); err != nil {
		t.Fatalf("新密码被误拒：%v", err)
	}
	if gotCount != 5 {
		t.Fatalf("count 透传 = %d, want 5", gotCount)
	}
}

// 配置防呆：零值不设防（普通 error，500 口径——配置 bug 不归 400）。
func TestHistoryCheckMisconfig(t *testing.T) {
	ctx := context.Background()
	bad := map[string]HistoryCheck{
		"Count=0":   {Fetch: func(context.Context, string, int) ([]string, error) { return nil, nil }, Match: plainMatch},
		"nil Fetch": {Count: 1, Match: plainMatch},
		"nil Match": {Count: 1, Fetch: func(context.Context, string, int) ([]string, error) { return nil, nil }},
	}
	for name, h := range bad {
		if err := h.Check(ctx, "u1", "x"); err == nil || IsViolation(err) {
			t.Fatalf("[%s] 必须是配置错误，got %v", name, err)
		}
	}
	good := HistoryCheck{
		Count: 1,
		Fetch: func(context.Context, string, int) ([]string, error) { return nil, nil },
		Match: plainMatch,
	}
	if err := good.Check(ctx, "", "x"); err == nil {
		t.Fatal("空 userID 必须报错")
	}
}
