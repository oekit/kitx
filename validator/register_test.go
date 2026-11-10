package validator

import (
	"errors"
	"strings"
	"testing"
)

// #94：RegisterValidation(tag, nil) 必须在注册期显式报错（ErrNilValidationFunc），
// 而不是把 nil 包进永不为 nil 的包装闭包后报告成功、等到校验期才 nil 指针崩溃
// ——门面绕过了上游的 fn==nil 守卫，必须自己再挡一道。
func TestRegisterValidation_NilFuncRejectedAtRegistration(t *testing.T) {
	if err := RegisterValidation("nil_rule_sweep4", nil); !errors.Is(err, ErrNilValidationFunc) {
		t.Fatalf("RegisterValidation(nil) = %v, want ErrNilValidationFunc", err)
	}
	// 实例路径同口径。
	pv := New()
	if err := pv.RegisterValidation("nil_rule_sweep4", nil); !errors.Is(err, ErrNilValidationFunc) {
		t.Fatalf("PlaygroundValidator.RegisterValidation(nil) = %v, want ErrNilValidationFunc", err)
	}
}

// #94：受限 tag（上游 restrictedTags 保留名 / 含受限字符）上游直接 panic，与
// 「返回 error」的签名契约相反——门面包一层 recover 转成 error，拼写错误的
// 保留 tag 不再打死进程。
func TestRegisterValidation_RestrictedTagReturnsErrorNotPanic(t *testing.T) {
	fn := func(val any) bool { return true }
	for _, tag := range []string{"required", "dive", "omitempty", "pipe|char"} {
		err := RegisterValidation(tag, fn)
		if err == nil {
			t.Fatalf("RegisterValidation(%q) 受限 tag 必须返回 error（而非 panic）", tag)
		}
		if !strings.Contains(err.Error(), tag) {
			t.Fatalf("RegisterValidation(%q) error = %v, 必须带上 tag 名", tag, err)
		}
	}
}

// #94：注册期 recover 后 tag 未注册、且不污染后续注册——同 tag 修好名字后可正常
// 注册使用。
func TestRegisterValidation_RestrictedTagThenValidTag(t *testing.T) {
	pv := New()
	bad := "required"
	if err := pv.RegisterValidation(bad, func(val any) bool { return true }); err == nil {
		t.Fatal("受限 tag 必须报错")
	}
	tag := "even_rule_sweep4"
	if err := pv.RegisterValidation(tag, func(val any) bool {
		v, ok := val.(int)
		return ok && v%2 == 0
	}); err != nil {
		t.Fatalf("RegisterValidation() error = %v, want nil", err)
	}
	if err := pv.ValidateVar(4, tag); err != nil {
		t.Fatalf("ValidateVar(4, %s) = %v, want nil", tag, err)
	}
	if err := pv.ValidateVar(3, tag); !IsValidationError(err) {
		t.Fatalf("ValidateVar(3, %s) = %v, want ValidationError", tag, err)
	}
}

// #94：规则自身 panic 在校验期就地隔离——转为「该规则校验失败」（false ⇒
// ValidationError 400 路径）并记 ERROR 日志，不再炸穿请求链。
func TestRegisterValidation_RulePanicIsolatedAtValidation(t *testing.T) {
	pv := New()
	tag := "panicky_rule_sweep4"
	if err := pv.RegisterValidation(tag, func(val any) bool { panic("boom") }); err != nil {
		t.Fatalf("RegisterValidation() error = %v, want nil", err)
	}
	err := pv.ValidateVar("x", tag)
	if !IsValidationError(err) {
		t.Fatalf("ValidateVar() = %v, want ValidationError（panic 被隔离为校验失败）", err)
	}
	ve, _ := AsValidationError(err)
	if ve.Len() != 1 || ve.Errors()[0].Tag != tag {
		t.Fatalf("errors = %v, want 单条 tag=%s 的字段错误", ve.Errors(), tag)
	}
	// 同一实例上其它规则不受影响（panic 隔离不污染校验器状态）。
	ok := "stable_rule_sweep4"
	if err := pv.RegisterValidation(ok, func(val any) bool { return true }); err != nil {
		t.Fatalf("RegisterValidation() error = %v", err)
	}
	if err := pv.ValidateVar("x", ok); err != nil {
		t.Fatalf("ValidateVar() = %v, want nil", err)
	}
}

// #94：正常路径回归——nil 守卫与 panic 隔离不得影响既有注册用法。
func TestRegisterValidation_NormalPathUnchanged(t *testing.T) {
	pv := New()
	tag := "nonempty_rule_sweep4"
	if err := pv.RegisterValidation(tag, func(val any) bool {
		s, ok := val.(string)
		return ok && len(s) > 0
	}); err != nil {
		t.Fatalf("RegisterValidation() error = %v", err)
	}
	if err := pv.ValidateVar("hello", tag); err != nil {
		t.Fatalf("ValidateVar() = %v, want nil", err)
	}
	if err := pv.ValidateVar("", tag); !IsValidationError(err) {
		t.Fatalf("ValidateVar() = %v, want ValidationError", err)
	}
}

// #115：上游内置校验器对「tag 与字段 Kind 不匹配」的非法组合（bool/struct 字段
// 挂 min 等）在校验期直接 panic（探针实证 "Bad field type bool" / "Bad field
// type <struct>"）——#94 三道闸（nil fn 注册拦截、注册期 panic 转 error、自定义
// 规则 invokeRule 隔离）一条都不覆盖这条路径，panic 原样穿透 Validate，与门面
// 「panic 不出网」承诺相反（tag 误写编译期无症状，第一次请求校验即炸穿请求链）。
// 修复前断言失败：panic 逃逸到调用方（测试自身兜 recover 把「逃逸」转成断言
// 失败，而不是炸掉整个测试进程）。
func TestValidate_EnginePanicTurnedToError(t *testing.T) {
	type badTagInner struct{ N int }
	pv := New()
	for name, obj := range map[string]any{
		"bool 挂 min": &struct {
			B bool `json:"b" validate:"min=1"`
		}{B: true},
		"struct 挂 min": &struct {
			S badTagInner `json:"s" validate:"min=1"`
		}{S: badTagInner{N: 5}},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] Validate() panic 穿透门面: %v（#115 闸缺失）", name, r)
				}
			}()
			err := pv.Validate(obj)
			if err == nil {
				t.Fatalf("[%s] tag 与字段 Kind 不匹配必须转为 error", name)
			}
			if IsValidationError(err) {
				t.Fatalf("[%s] tag 误用是服务端结构体定义 bug，不得归为 ValidationError 400，got %v", name, err)
			}
			if !strings.Contains(err.Error(), "panicked") {
				t.Fatalf("[%s] error = %v, want 点明校验期 panic", name, err)
			}
		}()
	}
}

// #115：ValidateVar/ValidateVarNamed 同口径（Var 路径直通同一上游引擎）；tag
// 参数自身非法（min=abc 的参数解析 panic）一并被闸住。
func TestValidateVar_EnginePanicTurnedToError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ValidateVar() panic 穿透门面: %v（#115 闸缺失）", r)
		}
	}()
	err := ValidateVar(true, "min=1")
	if err == nil {
		t.Fatal("ValidateVar(true, \"min=1\") 必须转为 error")
	}
	if IsValidationError(err) {
		t.Fatalf("tag 误用不得归为 ValidationError 400，got %v", err)
	}
	if !strings.Contains(err.Error(), "min=1") {
		t.Fatalf("error = %v, want 带上触发 tag 便于排障", err)
	}
	// ValidateVarNamed 走同一闸；tag 参数非法（min=abc）是另一 panic 形态。
	err = ValidateVarNamed(3, "payload", "min=abc")
	if err == nil || IsValidationError(err) {
		t.Fatalf("ValidateVarNamed(3, \"min=abc\") = %v, want 非 ValidationError 的 error", err)
	}
	if !strings.Contains(err.Error(), "min=abc") {
		t.Fatalf("error = %v, want 带上触发 tag", err)
	}
}
