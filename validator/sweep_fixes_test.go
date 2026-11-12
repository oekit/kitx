// 清零战役回归护栏（#150，2026-11-12 sweep）：SetDefault/Default 的 nil 守卫
// 对 typed-nil 同样成立，构造期 fail-fast 不落空。
package validator

import (
	"strings"
	"testing"
)

// #150：typed-nil（接口带着具体类型与 nil 指针）必须与无类型 nil 同拒——此前
// 守卫只判 v == nil，SetDefault((*PlaygroundValidator)(nil)) 绕过守卫存进去，
// 故障推迟到每一次 Validate 调用（每个请求吃一次 panic+recover+ERROR 日志，
// 文案还指向毫无关系的 tag/field-kind）。
func TestSetDefaultTypedNilPanics(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("SetDefault(typed-nil) 应 panic（#150：守卫不只挡无类型 nil）")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "nil") {
			t.Fatalf("panic 信息未说明是 nil 问题：%v", r)
		}
	}()
	var pv *PlaygroundValidator
	SetDefault(pv)
}

// #150：Default() 判据与 SetDefault 同口径收敛——typed-nil 存进去（直写 atomic
// 模拟历史遗留坏状态）时兜底返回可用验证器，而不是让每次 Validate 空指针崩溃。
func TestDefaultTypedNilFallback(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	var pv *PlaygroundValidator
	var v Validator = pv
	defaultValidator.Store(&v)

	got := Default()
	if got == nil {
		t.Fatal("Default() 返回了 nil 接口：调用方 Default().Validate(obj) 必崩")
	}
	// 兜底 New() 的返回类型也是 *PlaygroundValidator，按指针身份判定：
	// 返回的必须是新造的可用验证器，不是存进去的那个 typed-nil。
	if got == Validator(pv) {
		t.Fatal("typed-nil 必须被兜底替换为可用验证器（#150 两处判据同口径）")
	}
	if err := got.Validate(&struct {
		Name string `validate:"required"`
	}{}); err == nil {
		t.Fatal("兜底验证器应当能正常校验（空 Name 缺 required）")
	}
}

// 对照组：非 nil 的具体类型值不受守卫影响，正常存取。
func TestSetDefaultTypedNonNilOK(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	pv := New() // *PlaygroundValidator（指针接收者类型，typed-nil 案发的同一类型）
	SetDefault(pv)
	if Default() != pv {
		t.Fatal("非 nil 指针必须正常存取")
	}
}
