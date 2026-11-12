package pwd

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	bizerrors "github.com/oekit/pkg/errors"
)

// Kind 标注密码策略违规的类别（供调用方按类别定制响应文案/指标）。
type Kind string

const (
	// KindLength 长度违规（不足/超长）。
	KindLength Kind = "length"
	// KindComplexity 复杂度违规（缺字符类别）。
	KindComplexity Kind = "complexity"
	// KindWeak 弱口令违规（常见弱口令/结构性弱模式）。
	KindWeak Kind = "weak"
	// KindHistory 历史复用违规（与最近历史密码重复）。
	KindHistory Kind = "history"
)

// Violation 是密码策略违规错误：Message 为用户可读文案（可直接进响应），
// Unwrap 为 pkg/errors BizError 400（middleware.Fail 自动映射 HTTP 400，
// 与 validator.ValidationError 同款分型纪律）。
type Violation struct {
	// Kind 违规类别。
	Kind Kind
	// Message 用户可读文案（msgFormat/默认文案产物）。
	Message string
}

// Error 实现 error。
func (e *Violation) Error() string { return e.Message }

// Unwrap 返回 BizError 400（每次新值，message 与 Error() 一致——validator
// Unwrap 同款形态）：handler 层 errors.As 取到即 400，不落 500。
func (e *Violation) Unwrap() error { return bizerrors.NewBadRequestError(e.Message) }

// IsViolation 判定错误链里是否有密码策略违规（errors.As 链式匹配）。
func IsViolation(err error) bool {
	_, ok := AsViolation(err)
	return ok
}

// AsViolation 从错误链提取 Violation。
func AsViolation(err error) (*Violation, bool) {
	if err == nil {
		return nil, false
	}
	var v *Violation
	if errors.As(err, &v) {
		return v, true
	}
	return nil, false
}

// CheckMinLength 最小长度校验（#121 建议形态）：rune 口径（用户感知长度，
// 多字节密码不被字节数误杀）。
//
// msgFormat 是违规文案模板：为空用默认「密码至少 %d 个字符」；含 %d 占位符
// 时按 fmt.Sprintf(msgFormat, min) 格式化（约定 %d = 最小长度），不含 %d 时
// 按字面使用（避免 Sprintf 的 EXTRA 噪音）。违规返回 *Violation
// （Kind=KindLength，Unwrap 为 BizError 400）。min < 1 视为调用方配置 bug，
// 返回普通 error（归 500，#115 同口径）。
func CheckMinLength(password string, min int, msgFormat string) error {
	if min < 1 {
		return fmt.Errorf("pwd: CheckMinLength 的 min 必须 ≥ 1（got %d）——最小长度是密码策略的地板", min)
	}
	if n := len([]rune(password)); n < min {
		return &Violation{Kind: KindLength, Message: formatMsg(msgFormat, "密码至少 %d 个字符", min)}
	}
	return nil
}

// formatMsg 产出违规文案：空模板用默认模板，含 %d 占位符才 Sprintf，否则按字面。
func formatMsg(msgFormat, defFormat string, min int) string {
	if msgFormat == "" {
		msgFormat = defFormat
	}
	if strings.Contains(msgFormat, "%d") {
		return fmt.Sprintf(msgFormat, min)
	}
	return msgFormat
}

// Policy 是密码策略（#121）：长度/复杂度/常见弱口令拒绝面，Check 全量判据。
//
// 判定顺序固定（长度 → 复杂度 → 弱口令），一次返回首个违规——密码设置场景
// 给用户一条可执行的整改指引即可，聚合多条反而淹没重点（与 validator 的
// 字段聚合场景不同域）。
//
// 零值不设防，构造时 MinLength 必须显式 ≥ 1（Check 期 fail-fast 报配置错）：
// 「无最小长度的密码策略」是最危险的缺省（配置零值透传即全员短密码），
// 与 WithTTL(0) panic（jwt #65）同一纪律——此处以 error 表达（Check 有
// error 出口，策略配置 bug 归 500）。
type Policy struct {
	// MinLength 最小长度（rune 口径，必须 ≥ 1）。
	MinLength int
	// MaxLength 最大长度（rune 口径；0 = 不限）。防超长输入的存储/哈希层 DoS。
	MaxLength int
	// RequireUpper 要求含大写字母。
	RequireUpper bool
	// RequireLower 要求含小写字母。
	RequireLower bool
	// RequireDigit 要求含数字。
	RequireDigit bool
	// RequireSpecial 要求含特殊字符（非字母非数字，含空格）。
	RequireSpecial bool
}

// Check 校验密码是否满足策略（见 Policy 的判定顺序与配置契约）。
func (p Policy) Check(password string) error {
	if p.MinLength < 1 {
		return fmt.Errorf("pwd: Policy.MinLength 必须 ≥ 1（got %d）——最小长度是密码策略的地板，零值=无长度防线", p.MinLength)
	}
	if p.MaxLength < 0 {
		return fmt.Errorf("pwd: Policy.MaxLength 不能为负（got %d）——不限长请置 0", p.MaxLength)
	}
	runes := []rune(password)
	if err := CheckMinLength(password, p.MinLength, ""); err != nil {
		return err
	}
	if p.MaxLength > 0 && len(runes) > p.MaxLength {
		return &Violation{
			Kind:    KindLength,
			Message: fmt.Sprintf("密码至多 %d 个字符", p.MaxLength),
		}
	}
	var missing []string
	if p.RequireUpper && !containsFunc(runes, unicode.IsUpper) {
		missing = append(missing, "大写字母")
	}
	if p.RequireLower && !containsFunc(runes, unicode.IsLower) {
		missing = append(missing, "小写字母")
	}
	if p.RequireDigit && !containsFunc(runes, unicode.IsDigit) {
		missing = append(missing, "数字")
	}
	if p.RequireSpecial && !containsFunc(runes, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		missing = append(missing, "特殊字符")
	}
	if len(missing) > 0 {
		return &Violation{
			Kind:    KindComplexity,
			Message: fmt.Sprintf("密码须包含%s", strings.Join(missing, "、")),
		}
	}
	if weak, why := weakReason(password, runes); weak {
		return &Violation{Kind: KindWeak, Message: why}
	}
	return nil
}

// containsFunc 判定切片是否有满足谓词的元素。
func containsFunc(runes []rune, f func(rune) bool) bool {
	for _, r := range runes {
		if f(r) {
			return true
		}
	}
	return false
}

// weakReason 判定弱口令（#121 常见弱口令拒绝面）：命中则 (true, 文案)。
//
// 三层判定（纯 Go 零依赖的边界，非熵评估）：
//
//  1. 轻量 leet 归一后完全匹配内嵌常见弱口令表（p@ssw0rd → password 同拒）；
//  2. 弱核心子串（password/qwerty/123456 等）——"MyPassword123!" 同拒
//     （两侧同口径 leet 归一，#146）；
//  3. 结构性弱模式：全同字符（aaaaaaaa）、单向连续串（12345678/abcdefgh/
//     87654321）、键盘行连续（qwerty/asdf/zxcv 及其逆序的连续段）。
//
// runes 参数是 Check 已算好的 []rune(password)（#140：结构性弱模式判定复用它，
// 不再各自重做一次 []rune 转换）。
func weakReason(password string, runes []rune) (bool, string) {
	lower := strings.ToLower(password)
	// leet 归一只做一次（#140）：完全匹配与核心子串两层共用同一归一串——此前
	// 核心子串循环每轮重算 leetNormalize（weakCores 12 项 = 每密码 12 次冗余
	// 的逐 rune 字符串分配）。
	normalized := leetNormalize(lower)
	if _, ok := weakIndex()[normalized]; ok {
		return true, "密码过于常见（常见弱口令），请换一个"
	}
	for _, core := range weakCoresNormalized() {
		// 两侧同口径归一（#146）：core 比对前与 haystack 一起 leet 归一——
		// 此前只归一 haystack、core 存未归一原文，凡 core 含被映射字符
		// （"123456"→"i2eas6"、"abc123"→"abci2e"）在归一 haystack 里
		// 永远找不到，两条核心永久不可达，注释「归一后包含即拒」名不副实。
		if strings.Contains(normalized, core) {
			return true, "密码包含常见弱口令片段，请换一个"
		}
	}
	if sameRune(runes) {
		return true, "密码为单一字符重复，请换一个"
	}
	if consecutiveRun(runes) {
		return true, "密码为连续字符序列，请换一个"
	}
	if keyboardRun(lower) {
		return true, "密码为键盘连续序列，请换一个"
	}
	return false, ""
}

// leetNormalize 轻量 leet 归一（0→o、1→i、3→e、@→a 等常见替换回字母），
// 让 p@ssw0rd / p4ssw0rd 之类落在同一拒绝口径。
func leetNormalize(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '0':
			return 'o'
		case '1':
			return 'i'
		case '3':
			return 'e'
		case '4':
			return 'a'
		case '5':
			return 's'
		case '7':
			return 't'
		case '@':
			return 'a'
		case '$':
			return 's'
		case '!':
			return 'i'
		default:
			return r
		}
	}, s)
}

// sameRune 判定全同字符（≥ 3 个相同字符即弱，aaaaaaaa / 11111111）。
// runes 由调用方复用传入（#140，weakReason/Check 不再重复转换）。
func sameRune(runes []rune) bool {
	if len(runes) < 3 {
		return false
	}
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// consecutiveRun 判定单向连续串（相邻字符恒 +1 或恒 -1，≥ 4 个字符：
// 12345678 / 87654321 / abcd / hgfe）。runes 由调用方复用传入（#140）。
func consecutiveRun(runes []rune) bool {
	if len(runes) < 4 {
		return false
	}
	up, down := true, true
	for i := 1; i < len(runes); i++ {
		switch runes[i] - runes[i-1] {
		case 1:
			down = false
		case -1:
			up = false
		default:
			return false
		}
	}
	return up || down
}

// keyboardRun 判定键盘行连续段（密码（小写）是任一键盘行或其逆序的连续
// 子串，≥ 4 个字符：qwer / uiop / kjhg / nmbv）。
func keyboardRun(lower string) bool {
	if len([]rune(lower)) < 4 {
		return false
	}
	for _, row := range keyboardRows {
		if strings.Contains(row, lower) || strings.Contains(reverseString(row), lower) {
			return true
		}
	}
	return false
}

// reverseString 反转字符串（键盘行逆序判定用）。
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// keyboardRows 键盘行（小写）。
var keyboardRows = []string{"qwertyuiop", "asdfghjkl", "zxcvbnm"}

// weakCores 弱核心子串（原文表；比对前两侧一起 leet 归一，#146——归一形态见
// weakCoresNormalized）。
var weakCores = []string{
	"password", "qwerty", "abc123", "123456", "admin", "letmein",
	"iloveyou", "welcome", "login", "master", "sunshine", "princess",
}

// weakCoresNormalized 是 weakCores 的 leet 归一形态（懒建一次，weakIndex 同款
// 纪律：表只建一次，包级只读共享，无锁热路径；#146 两侧同口径 + #140 不在
// 判定循环里逐次分配）。
var weakCoresNormalized = sync.OnceValue(func() []string {
	out := make([]string, len(weakCores))
	for i, core := range weakCores {
		out[i] = leetNormalize(core)
	}
	return out
})

// weakIndex 是内嵌常见弱口令表的归一索引（sync.OnceValue 懒建——表只建
// 一次，包级只读共享，无锁热路径）。
var weakIndex = sync.OnceValue(func() map[string]struct{} {
	idx := make(map[string]struct{}, len(commonWeak))
	for _, w := range commonWeak {
		idx[leetNormalize(w)] = struct{}{}
	}
	return idx
})

// commonWeak 内嵌常见弱口令表（公开弱口令榜单高频项，小表即可挡住批量
// 试探的头部分布；非穷举——熵评估请接专用库，本包边界见包文档）。
var commonWeak = []string{
	"123456", "123456789", "12345678", "12345", "1234567", "1234567890",
	"password", "password1", "password123", "passw0rd", "qwerty", "qwerty123",
	"abc123", "abcd1234", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "qazwsx",
	"111111", "000000", "123123", "123321", "654321", "666666", "888888",
	"admin", "administrator", "root", "guest", "test", "demo", "default",
	"letmein", "welcome", "welcome1", "login", "master", "secret", "iloveyou",
	"sunshine", "princess", "football", "baseball", "soccer", "hockey",
	"monkey", "dragon", "shadow", "superman", "batman", "starwars", "trustno1",
	"hello", "hello123", "freedom", "whatever", "nothing", "internet",
	"computer", "samsung", "google", "facebook", "michael", "jennifer",
	"jordan", "harley", "ranger", "buster", "thomas", "robert", "matrix",
	"ashley", "nicole", "chelsea", "biteme", "access", "mustang", "money",
	"charlie", "aa123456", "donald", "qwertyuiop", "asdfghjkl", "zxcvbnm",
}
