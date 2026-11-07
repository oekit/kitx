package validator

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateVar_FieldNameNotLost 回归测试：单变量校验的错误必须带得出手的
// 字段名（或至少是兜底主语），不能是残缺文本。
//
// 缺陷成因：底层 go-playground/validator 的 Var 路径不返回字段名
// （fe.Field() == ""）⇒ 错误消息是 " is required"（前导空格、没有主语），
// ValidationError.Map() 还多出一个空字符串键 ""——直接喂 JSON 响应会得到
// {"": " is required"}。
func TestValidateVar_FieldNameNotLost(t *testing.T) {
	err := ValidateVar("", "required")
	if err == nil {
		t.Fatal("期望校验失败")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("期望 *ValidationError，实得 %T", err)
	}
	if ve.Len() != 1 {
		t.Fatalf("错误数 = %d，期望 1", ve.Len())
	}
	fe := ve.Errors()[0]
	if fe.Field == "" {
		t.Fatal("字段名为空 ⇒ 调用方无法知道是哪个字段没过")
	}
	if strings.HasPrefix(fe.Message, " ") {
		t.Fatalf("消息有前导空格（残缺文本）：%q", fe.Message)
	}
	if !strings.Contains(fe.Message, fe.Field) {
		t.Fatalf("消息 %q 不含字段名 %q", fe.Message, fe.Field)
	}
	// Map() 不应出现空键
	for k := range ve.Map() {
		if k == "" {
			t.Fatal("Map() 出现空键")
		}
	}
}

// TestValidateVarNamed_UsesGivenFieldName 回归测试：带字段名的变体必须把
// 调用方给的字段名写进消息与结构化错误。
func TestValidateVarNamed_UsesGivenFieldName(t *testing.T) {
	err := ValidateVarNamed("", "email", "required,email")
	if err == nil {
		t.Fatal("期望校验失败")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("期望 *ValidationError，实得 %T", err)
	}
	fe := ve.Errors()[0]
	if fe.Field != "email" {
		t.Fatalf("字段名 = %q，期望 %q", fe.Field, "email")
	}
	if !strings.Contains(fe.Message, "email") {
		t.Fatalf("消息 %q 不含字段名", fe.Message)
	}
	m := ve.Map()
	if _, ok := m["email"]; !ok {
		t.Fatalf("Map() 缺少 email 键：%v", m)
	}
}

// TestValidateVarNamed_EmptyFieldName_FallsBack 护栏：字段名为空时退化为
// 兜底主语，不产生空键。
func TestValidateVarNamed_EmptyFieldName_FallsBack(t *testing.T) {
	err := ValidateVarNamed("", "", "required")
	if err == nil {
		t.Fatal("期望校验失败")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("期望 *ValidationError，实得 %T", err)
	}
	if ve.Errors()[0].Field == "" {
		t.Fatal("空字段名未回退到兜底主语")
	}
}

// TestValidate_KeepsRealFieldName 护栏：结构体校验路径仍用真实字段名
// （不受单变量兜底主语影响）。
func TestValidate_KeepsRealFieldName(t *testing.T) {
	type req struct {
		Email string `json:"email" validate:"required,email"`
	}
	err := Validate(&req{})
	if err == nil {
		t.Fatal("期望校验失败")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("期望 *ValidationError，实得 %T", err)
	}
	fe := ve.Errors()[0]
	if fe.Field != "email" {
		t.Fatalf("字段名 = %q，期望 %q（json tag 名）", fe.Field, "email")
	}
	if !strings.Contains(fe.Message, "email") {
		t.Fatalf("消息 %q 不含字段名", fe.Message)
	}
}

// TestValidateVar_MinMaxMessageByKind 回归测试（#73）：min/max 的措辞必须按
// 字段类型区分——数值字段是值边界（"must be at least/most"），字符串/切片等
// 才是长度（"length must be at least/most"）。
//
// 缺陷成因：formatMessageNamed 的 min/max 分支硬编码 "length must be
// at least/most"——go-playground 对 int/float 的 min/max 是值边界，数值字段
// 的消息变成了错误陈述，用户按消息改「长度」永远过不了校验。
func TestValidateVar_MinMaxMessageByKind(t *testing.T) {
	cases := []struct {
		name    string
		value   any
		field   string
		tag     string
		wantMsg string
	}{
		// 数值边界：消息不得出现 "length"。
		{"numeric min", 18, "age", "min=21", "age must be at least 21"},
		{"numeric max", 200, "age", "max=150", "age must be at most 150"},
		// 字符串长度：措辞保持不变（护栏）。
		{"string min", "ab", "name", "min=3", "name length must be at least 3"},
		{"string max", "toolong", "name", "max=5", "name length must be at most 5"},
	}
	for _, tc := range cases {
		err := ValidateVarNamed(tc.value, tc.field, tc.tag)
		if err == nil {
			t.Fatalf("[%s] 期望校验失败", tc.name)
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("[%s] 期望 *ValidationError，实得 %T", tc.name, err)
		}
		fe := ve.Errors()[0]
		if fe.Message != tc.wantMsg {
			t.Errorf("[%s] 消息 = %q, 期望 %q", tc.name, fe.Message, tc.wantMsg)
		}
	}
}
