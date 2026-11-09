package validator

import (
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/oekit/logx"
)

// log 是本包的懒解析日志器（SDK/基础包规范：Delegating，禁止 Default()）。
var log = logx.Delegating("kitx/validator")

// PlaygroundValidator 是基于 go-playground/validator 的验证器实现。
type PlaygroundValidator struct {
	validate *validator.Validate
}

// New 创建 PlaygroundValidator 实例。
func New() *PlaygroundValidator {
	v := validator.New()

	// 使用 json tag 作为字段名
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		if name == "" {
			return fld.Name
		}
		return name
	})

	return &PlaygroundValidator{validate: v}
}

// Validate 验证结构体。
func (pv *PlaygroundValidator) Validate(obj any) error {
	err := pv.validate.Struct(obj)
	if err == nil {
		return nil
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	fieldErrors := make([]FieldError, 0, len(validationErrors))
	for _, fe := range validationErrors {
		fieldErrors = append(fieldErrors, FieldError{
			Field:   fe.Field(),
			Tag:     fe.Tag(),
			Param:   fe.Param(),
			Message: formatMessage(fe),
		})
	}

	return NewFieldValidationError(fieldErrors)
}

// ValidateVar 验证单个变量。
//
// **没有字段名可用**：底层 go-playground/validator 的 Var 路径不提供字段名
// （fe.Field() 为空串）⇒ 此前错误消息是 " is required"（前导空格、没有主语），
// ValidationError.Map() 还会多出一个空字符串键 ""。这里用 "value" 作兜底主语；
// 需要真实字段名请用 ValidateVarNamed。
func (pv *PlaygroundValidator) ValidateVar(field any, tag string) error {
	return pv.validateVar(field, defaultVarFieldName, tag)
}

// ValidateVarNamed 验证单个变量并带上字段名。
//
// 错误消息的主语与 ValidationError.Map() 的键都用 fieldName——
// 单变量校验最常见的用法（逐字段校验请求参数）需要知道是**哪个**字段没过。
func (pv *PlaygroundValidator) ValidateVarNamed(field any, fieldName string, tag string) error {
	if fieldName == "" {
		fieldName = defaultVarFieldName
	}
	return pv.validateVar(field, fieldName, tag)
}

// validateVar 执行单变量校验并组装结构化错误。
//
// fieldName 只在底层给不出字段名（Var 路径）时兜底；结构体校验路径
// （Validate）始终用真实的结构体字段名。
func (pv *PlaygroundValidator) validateVar(field any, fieldName string, tag string) error {
	err := pv.validate.Var(field, tag)
	if err == nil {
		return nil
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	fieldErrors := make([]FieldError, 0, len(validationErrors))
	for _, fe := range validationErrors {
		name := fe.Field()
		if name == "" {
			name = fieldName
		}
		fieldErrors = append(fieldErrors, FieldError{
			Field:   name,
			Tag:     fe.Tag(),
			Param:   fe.Param(),
			Message: formatMessageNamed(fe, name),
		})
	}

	return NewFieldValidationError(fieldErrors)
}

// RegisterValidation 注册自定义验证规则。
//
// 门面补三道闸（#94）：
//   - fn == nil 注册期显式拦下（ErrNilValidationFunc）：门面把 fn 包进永不为
//     nil 的闭包再传上游，上游的 fn==nil 守卫全部失效——此前 nil 规则注册期
//     报告成功、第一次用到该 tag 的线上流量才 nil 指针崩溃；
//   - 上游对受限 tag（required 等保留名或含受限字符）直接 panic，与「返回
//     error」的签名契约相反——包一层 recover 转成 error，一个拼写错误的保留
//     tag 不再打死进程；
//   - 规则自身 panic 在校验期就地隔离（invokeRule）：转为「该规则校验失败」
//     （false ⇒ 走 ValidationError 400 路径）并记 ERROR 日志带 stack，与
//     registry/nacosimpl 订阅回调、registry/nacos 配置回调对「消费方回调质量
//     不可控」的隔离口径一致。
//
// ⚠️ 与包级 RegisterValidation 相同：必须在 init 阶段（任何 Struct 校验开始前）
// 调用——底层注册写内部 map 与校验读并发不安全。
func (pv *PlaygroundValidator) RegisterValidation(tag string, fn Func) (err error) {
	if fn == nil {
		return ErrNilValidationFunc
	}
	defer func() {
		if r := recover(); r != nil {
			// 上游对受限 tag 直接 panic（validator_instance.go）：转成 error
			// 返回，兑现 error 契约。tag 未注册，后续校验按未知 tag 处理。
			err = fmt.Errorf("validator: register rule %q: %v", tag, r)
		}
	}()
	return pv.validate.RegisterValidation(tag, func(fl validator.FieldLevel) bool {
		return invokeRule(tag, fn, fl.Field().Interface())
	})
}

// invokeRule 调用规则函数并就地隔离 panic（#94）：规则内部 panic（忘了判 nil、
// 除零、索引越界）不炸穿请求链，转为该字段校验失败 + ERROR 日志。
func invokeRule(tag string, fn Func, val any) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("custom validation rule panicked (isolated)",
				"tag", tag, logx.ErrKey, r, "stack", string(debug.Stack()))
			ok = false
		}
	}()
	return fn(val)
}

// RegisterTranslation 注册验证错误的翻译。
//
// 当前实现不支持翻译引擎：错误消息已通过 formatMessage English prompts via formatMessage。
// 调用将始终返回 ErrTranslationNotSupported，避免调用方误以为翻译已注册成功。
// 如需自定义消息，请扩展 formatMessage 或实现自定义 Validator。
func (pv *PlaygroundValidator) RegisterTranslation(locale, tag, msg string) error {
	return ErrTranslationNotSupported
}

// Validate_ 返回底层验证器实例，供高级用户直接使用。
func (pv *PlaygroundValidator) Validate_() *validator.Validate {
	return pv.validate
}

// defaultVarFieldName 是单变量校验在拿不到字段名时的兜底主语。
//
// 底层 go-playground/validator 的 Var 路径不返回字段名（fe.Field() == ""），
// 直接用会得到 " is required" 这种前导空格的残缺消息，以及 Map() 里的空键。
const defaultVarFieldName = "value"

// formatMessage 生成友好的错误消息（字段名取底层的 fe.Field()）。
func formatMessage(fe validator.FieldError) string {
	return formatMessageNamed(fe, fe.Field())
}

// formatMessageNamed 生成友好的错误消息，字段名用 name。
//
// name 为空时依次回退 fe.Field() 与 defaultVarFieldName ⇒ 消息永远有主语，
// 不会出现 " is required" 这种残缺文本。
func formatMessageNamed(fe validator.FieldError, name string) string {
	if name == "" {
		name = fe.Field()
	}
	if name == "" {
		name = defaultVarFieldName
	}
	field := name
	tag := fe.Tag()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		if isLengthKind(fe.Kind()) {
			return fmt.Sprintf("%s length must be at least %s", field, fe.Param())
		}
		return fmt.Sprintf("%s must be at least %s", field, fe.Param())
	case "max":
		if isLengthKind(fe.Kind()) {
			return fmt.Sprintf("%s length must be at most %s", field, fe.Param())
		}
		return fmt.Sprintf("%s must be at most %s", field, fe.Param())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", field, fe.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", field, fe.Param())
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, fe.Param())
	case "lt":
		return fmt.Sprintf("%s must be less than %s", field, fe.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, fe.Param())
	case "len":
		return fmt.Sprintf("%s length must be %s", field, fe.Param())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "uri":
		return fmt.Sprintf("%s must be a valid URI", field)
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", field)
	case "numeric":
		return fmt.Sprintf("%s must be numeric", field)
	case "alpha":
		return fmt.Sprintf("%s must contain only letters", field)
	case "alphanum":
		return fmt.Sprintf("%s must contain only letters and numbers", field)
	default:
		return fmt.Sprintf("%s validation failed (%s)", field, tag)
	}
}

// isLengthKind 判断该 Kind 上 go-playground 的 min/max 语义是长度而非数值
// 边界（string/slice/map/array；数值 Kind 的 min/max 是值边界，非长度的
// Kind 一律按值边界措辞）。#73：min/max 分支此前恒写 "length must be"——
// 对 int/float 字段是错误陈述，用户按消息改「长度」永远过不了校验。
func isLengthKind(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return true
	default:
		return false
	}
}
