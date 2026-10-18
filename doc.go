// Package kitx 是 oekit 的标识与校验工具仓。
//
// 自 oekit/pkg v0.10.0 拆分而来，包含三个子包：
//
//   - hash：非密码学哈希助手（Md5Hex/Md5Bytes——缓存键/幂等键/短唯一 code，
//     格式稳定承诺；pkg#10 收编，pkg/encoding 的治理移除决定保持不变）
//   - uidgen：分布式唯一 ID（Snowflake 全局单例 + Extract 元数据）、
//     RFC 4122 v4 UUID（标准库手写，零第三方依赖）、crypto/rand 随机串
//     （RandomHex / 拒绝采样 RandomString）
//   - validator：go-playground/validator 接口化门面——struct tag 校验、
//     自定义规则注册、ValidationError（Unwrap 为 pkg/errors BizError 400，
//     middleware.Fail 自动映射 HTTP 400）
//
// 基础微工具（errors/stringx/timex/container 等）仍在 github.com/oekit/pkg。
package kitx
