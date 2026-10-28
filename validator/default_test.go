package validator

import (
	"strings"
	"testing"
)

// TestSetDefaultNil 回归测试：SetDefault(nil) 不得让后续校验崩溃。
//
// 缺陷成因：SetDefault 直接把 nil 存进 atomic 指针 ⇒ Default() 返回 nil 接口
// ⇒ 后续每一次 Default().Validate(obj) 都是**空指针崩溃**，而且崩在调用方、
// 栈里只有 "validator.Default().Validate" 这一行，看不出根因是这里存了个
// nil。
func TestSetDefaultNil(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("SetDefault(nil) 应 panic（快速失败）")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "nil") {
			t.Fatalf("panic 信息未说明是 nil 问题：%v", r)
		}
	}()

	SetDefault(nil)
}

// TestDefaultSurvivesNilDefault 兜底：即使默认验证器被置成 nil，Default() 也要
// 返回可用的验证器而不是在解引用处崩。
func TestDefaultSurvivesNilDefault(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	// 直接把 atomic 指针置成「装着 nil 接口的指针」，模拟历史遗留的坏状态。
	var nilValidator Validator
	defaultValidator.Store(&nilValidator)

	got := Default()
	if got == nil {
		t.Fatal("Default() 返回了 nil：调用方 Default().Validate(obj) 必崩")
	}
	if err := got.Validate(&struct {
		Name string `validate:"required"`
	}{}); err == nil {
		t.Fatal("兜底验证器应当能正常校验（空 Name 缺 required）")
	}
}

// TestSetDefaultNormal 正常路径：SetDefault 一个真实验证器后 Default() 返回它。
func TestSetDefaultNormal(t *testing.T) {
	old := Default()
	t.Cleanup(func() { SetDefault(old) })

	custom := New()
	SetDefault(custom)
	if Default() != custom {
		t.Fatal("Default() 应返回刚设置的验证器")
	}
}
