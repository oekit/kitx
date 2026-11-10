package pwd

import (
	"errors"
	"strings"
	"testing"

	bizerrors "github.com/oekit/pkg/errors"
)

// CheckMinLength：rune 口径 + 文案模板两形态 + 配置防呆。
func TestCheckMinLength(t *testing.T) {
	if err := CheckMinLength("12345678", 8, ""); err != nil {
		t.Fatalf("恰到最小长度应通过，got %v", err)
	}
	if err := CheckMinLength("1234567", 8, ""); err == nil {
		t.Fatal("短于最小长度必须违规")
	}
	// rune 口径：8 个中文字符是 8 个字符（24 字节），不得按字节误杀。
	if err := CheckMinLength("密码密码密码密码", 8, ""); err != nil {
		t.Fatalf("rune 口径误杀多字节密码：%v", err)
	}
	if err := CheckMinLength("密码密码密码", 8, ""); err == nil {
		t.Fatal("7 个 rune 必须违规")
	}
	// 违规形态：Kind + BizError 400 + 默认文案。
	err := CheckMinLength("short", 8, "")
	var v *Violation
	if !errors.As(err, &v) || v.Kind != KindLength {
		t.Fatalf("违规错误 = %v, want *Violation(KindLength)", err)
	}
	if v.Message != "密码至少 8 个字符" {
		t.Fatalf("默认文案 = %q", v.Message)
	}
	var biz *bizerrors.BizError
	if !errors.As(err, &biz) || biz.HTTPCode != 400 {
		t.Fatalf("Unwrap 必须是 BizError 400，got %v", err)
	}
	if !IsViolation(err) {
		t.Fatal("IsViolation 必须命中")
	}
	// msgFormat：含 %d 代入 min；不含 %d 按字面。
	if err := CheckMinLength("short", 10, "口令长度不足 %d 位"); err == nil || err.Error() != "口令长度不足 10 位" {
		t.Fatalf("msgFormat 模板 = %v", err)
	}
	if err := CheckMinLength("short", 10, "口令太短"); err == nil || err.Error() != "口令太短" {
		t.Fatalf("msgFormat 字面 = %v", err)
	}
	// 配置 bug 归普通 error（500 口径，#115 同款分型），不是 Violation。
	if err := CheckMinLength("x", 0, ""); err == nil || IsViolation(err) {
		t.Fatalf("min<1 必须是配置错误，got %v", err)
	}
}

// Policy.Check：长度/复杂度/弱口令三层 + 判定顺序固定。
func TestPolicyCheck(t *testing.T) {
	strict := Policy{
		MinLength:      8,
		MaxLength:      16,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
	}
	if err := strict.Check("Xk9#mQ2$vL"); err != nil {
		t.Fatalf("强密码被拒：%v", err)
	}
	for name, tc := range map[string]struct {
		pwd  string
		kind Kind
	}{
		"太短":    {"Ab1!", KindLength},
		"超长":    {"Xk9#mQ2$vLXk9#mQ2$vLX", KindLength},
		"缺大写":   {"xk9#mq2$v", KindComplexity},
		"缺小写":   {"XK9#MQ2$V", KindComplexity},
		"缺数字":   {"Xk##mQ$$vL", KindComplexity},
		"缺特殊":   {"Xk98mQ25vL", KindComplexity},
		"弱口令变体": {"P@ssw0rd", KindWeak}, // 复杂度全过也拒（leet 归一命中表）
	} {
		err := strict.Check(tc.pwd)
		var v *Violation
		if !errors.As(err, &v) {
			t.Fatalf("[%s] 必须违规，got %v", name, err)
		}
		if v.Kind != tc.kind {
			t.Fatalf("[%s] Kind = %s, want %s（判定顺序：长度→复杂度→弱口令）", name, v.Kind, tc.kind)
		}
	}
	// 弱口令拒绝面（长度口径隔离，模式见 TestPolicyWeakDenylist）。
	lenient := Policy{MinLength: 8}
	for name, pwd := range map[string]string{
		"常见弱口令": "password",
		"弱核心子串": "MyPassword123!",
		"全同字符":  "aaaaaaaa",
		"连续升序":  "12345678",
		"连续降序":  "87654321",
		"字母升序":  "abcdefgh",
		"键盘行连续": "qwertyui",
		"键盘行逆序": "poiuytre",
	} {
		var v *Violation
		if err := lenient.Check(pwd); !errors.As(err, &v) || v.Kind != KindWeak {
			t.Fatalf("[%s] 必须判弱口令，got %v", name, pwd)
		}
	}
	// 判定顺序：长度先于复杂度（短且缺大写 → length）。
	var v *Violation
	if err := strict.Check("abc"); !errors.As(err, &v) || v.Kind != KindLength {
		t.Fatalf("判定顺序错乱：%v", err)
	}
}

// 弱口令表覆盖：leet 归一 + 大小写。
func TestPolicyWeakDenylist(t *testing.T) {
	p := Policy{MinLength: 4} // 只开长度，隔离弱口令判定
	for _, pwd := range []string{
		"123456", "PASSWORD", "password1", "passw0rd", "p4ssw0rd", "qwerty123",
		"letmein", "admin123", "iloveyou", "trustno1", "aa123456", "1qaz2wsx",
	} {
		var v *Violation
		if err := p.Check(pwd); !errors.As(err, &v) || v.Kind != KindWeak {
			t.Fatalf("%q 必须判弱口令，got %v", pwd, err)
		}
	}
	for _, pwd := range []string{"Xk9#mQ2$vL", "correct horse battery staple", "Zebra-9-River"} {
		if err := p.Check(pwd); err != nil {
			t.Fatalf("%q 不该被拒：%v", pwd, err)
		}
	}
}

// Policy 配置防呆：MinLength 地板（普通 error，500 口径）。
func TestPolicyMisconfig(t *testing.T) {
	if err := (Policy{}).Check("x"); err == nil || IsViolation(err) {
		t.Fatalf("MinLength=0 必须是配置错误，got %v", err)
	}
	if err := (Policy{MinLength: 8, MaxLength: -1}).Check("Xk9#mQ2$vL"); err == nil || IsViolation(err) {
		t.Fatalf("MaxLength<0 必须是配置错误，got %v", err)
	}
}

// AsViolation 从错误链提取。
func TestAsViolation(t *testing.T) {
	if _, ok := AsViolation(nil); ok {
		t.Fatal("nil 不得命中")
	}
	if _, ok := AsViolation(errors.New("plain")); ok {
		t.Fatal("普通错误不得命中")
	}
	err := CheckMinLength("x", 8, "")
	if v, ok := AsViolation(err); !ok || !strings.Contains(v.Message, "8") {
		t.Fatalf("AsViolation = (%v, %v)", v, ok)
	}
}
