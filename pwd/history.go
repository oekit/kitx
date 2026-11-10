package pwd

import (
	"context"
	"fmt"
)

// HistorySource 历史密码取数面：返回该用户最近 count 条历史密码的**存储形态**
// （典型 bcrypt hash，顺序不限，逐条比对）。存储形态而非明文——历史表落的
// 本来就是哈希。
type HistorySource func(ctx context.Context, userID string, count int) ([]string, error)

// Matcher 历史比对器：候选明文与存储形态比对（典型
// bcrypt.CompareHashAndPassword 包装：`func(stored, candidate string) (bool, error) {
// return nil == bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) }`）。
//
// 库层不绑哈希算法（纯 Go 零依赖是本包边界）：比对语义由调用方注入，错误
// 形态（哈希格式坏等）经 error 上抛，HistoryCheck 按 fail-closed 处理。
type Matcher func(stored, candidate string) (bool, error)

// HistoryCheck 历史防复用检查（#121）：候选密码不得与最近 Count 条历史密码
// 重复。
//
// fail-closed 契约（#121 的核心取舍）：Fetch/Match 出错 ≠ 放行——历史查询
// 失败时绝不能降级成「没查到历史 ⇒ 新密码可用」，错误原样上抛（归 500），
// 让调用方决定重试还是失败。命中任一历史 ⇒ *Violation（Kind=KindHistory，
// 400）。
//
// 零值不设防，Count 必须显式 ≥ 1 且 Fetch/Match 非 nil（Check 期 fail-fast
// 报配置错，归 500——配置 bug 不归 400，#115 同口径）。
type HistoryCheck struct {
	// Count 回溯条数（必须 ≥ 1）。
	Count int
	// Fetch 历史取数面（必须非 nil）。
	Fetch HistorySource
	// Match 哈希比对器（必须非 nil）。
	Match Matcher
}

// Check 判定候选密码是否与历史重复（契约见 HistoryCheck）。
func (h HistoryCheck) Check(ctx context.Context, userID, candidate string) error {
	if h.Count < 1 || h.Fetch == nil || h.Match == nil {
		return fmt.Errorf("pwd: HistoryCheck 配置非法（Count≥1 且 Fetch/Match 非 nil 才启用历史防复用）")
	}
	if userID == "" {
		return fmt.Errorf("pwd: HistoryCheck 的 userID 不能为空")
	}
	history, err := h.Fetch(ctx, userID, h.Count)
	if err != nil {
		return fmt.Errorf("pwd: 历史密码查询失败（fail-closed，不放行）: %w", err)
	}
	for _, stored := range history {
		hit, err := h.Match(stored, candidate)
		if err != nil {
			return fmt.Errorf("pwd: 历史密码比对失败（fail-closed，不放行）: %w", err)
		}
		if hit {
			return &Violation{Kind: KindHistory, Message: "新密码与近期使用过的密码重复，请换一个"}
		}
	}
	return nil
}
