package validator

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	bizerrors "github.com/oekit/pkg/errors"
)

// ErrNilValidationFunc 表示注册自定义验证规则时传入了 nil 函数（#94）。
// 注册期显式拦下而非推迟到校验期才炸出 nil 指针 panic——上游
// go-playground/validator 的 fn==nil 守卫会被门面的包装闭包绕过
// （闭包本身永不为 nil），门面必须自己再挡一道。
var ErrNilValidationFunc = errors.New("validator: validation func must not be nil")

// ErrTranslationNotSupported 表示当前验证器不支持错误消息翻译。
// PlaygroundValidator 的错误消息已通过 formatMessage 内置英文提示，
// 如需自定义消息请扩展 formatMessage 或实现自定义 Validator。
var ErrTranslationNotSupported = errors.New("validator: translation not supported; messages are built-in via formatMessage")

// ValidationError 包含多个字段验证错误。
// 实现 BizError 接口（code=400），handler 层的 Fail 会自动识别为 400 Bad Request。
type ValidationError struct {
	errors []FieldError
}

// FieldError 表示单个字段的验证错误。
type FieldError struct {
	Field   string `json:"field"`           // 字段名
	Tag     string `json:"tag"`             // 验证标签
	Param   string `json:"param,omitempty"` // 标签参数
	Message string `json:"message"`         // 错误消息
}

// Error 实现 error 接口，返回第一个错误消息。
func (e *ValidationError) Error() string {
	if len(e.errors) == 0 {
		return "validation failed"
	}
	return e.errors[0].Message
}

// Unwrap 返回底层的 BizError（BizCode=400, HTTPCode=400），使 errors.As 能识别为 BizError。
// 这样 handler 层的 Fail 会自动返回 400 Bad Request，而非 500。
func (e *ValidationError) Unwrap() error {
	return bizerrors.NewBizErrorWithStatus(400, 400, e.Error())
}

// Errors 返回所有字段错误（副本，#116）：返回值与内部存储不共享底层数组——
// 调用方排序/改写返回值不得影响错误值自身的 Error()/Map()/String()。错误值在
// Go 里按惯例不可变（core#80 同款快照纪律：已发布的快照不可被事后改写）。
func (e *ValidationError) Errors() []FieldError {
	return slices.Clone(e.errors)
}

// Map 返回 field→message 映射，适用于 JSON 响应。
func (e *ValidationError) Map() map[string]string {
	m := make(map[string]string, len(e.errors))
	for _, fe := range e.errors {
		m[fe.Field] = fe.Message
	}
	return m
}

// Len 返回错误数量。
func (e *ValidationError) Len() int {
	return len(e.errors)
}

// String 实现 fmt.Stringer。
func (e *ValidationError) String() string {
	var sb strings.Builder
	sb.WriteString("validation failed: ")
	for i, fe := range e.errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%s (%s)", fe.Field, fe.Tag)
	}
	return sb.String()
}

// NewFieldValidationError 创建包含指定字段错误的验证错误（构造期拷贝入参，
// #116）。供 handler/validatorh 等外部包构造 ValidationError。入参与内部存储
// 不共享底层数组（slices.Clone）——调用方构造后复用底层数组做日志增强/翻译
// 不得让已返回给调用方的错误值内容事后漂移（构造与 Errors() 读取双向别名在
// 此切断，core#80 同构）。
func NewFieldValidationError(fieldErrs []FieldError) *ValidationError {
	return &ValidationError{errors: slices.Clone(fieldErrs)}
}

// IsValidationError 检查错误是否为 ValidationError 类型。
func IsValidationError(err error) bool {
	_, ok := AsValidationError(err)
	return ok
}

// AsValidationError 从错误链中提取 ValidationError（支持 errors.As 链式匹配）。
func AsValidationError(err error) (*ValidationError, bool) {
	if err == nil {
		return nil, false
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
