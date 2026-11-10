// Package kitx 是 oekit 的标识与校验工具仓。
//
// 自 oekit/pkg v0.10.0 拆分而来，包含以下子包：
//
//   - hash：非密码学哈希助手（Md5Hex/Md5Bytes——缓存键/幂等键/短唯一 code，
//     格式稳定承诺；pkg#10 收编，pkg/encoding 的治理移除决定保持不变）
//   - uidgen：分布式唯一 ID（Snowflake 全局单例 + Extract 元数据）、
//     RFC 4122 v4 UUID（标准库手写，零第三方依赖）、crypto/rand 随机串
//     （RandomHex / 拒绝采样 RandomString）
//   - validator：go-playground/validator 接口化门面——struct tag 校验、
//     自定义规则注册、ValidationError（Unwrap 为 pkg/errors BizError 400，
//     middleware.Fail 自动映射 HTTP 400）；单变量校验用 ValidateVarNamed
//     带字段名（ValidateVar 的字段名退化为兜底主语 "value"）
//   - jwt：JWT 签发与校验（RS256/HS256 双形态、Manager 双令牌对
//     IssuePair/ParseTyped/Refresh，#86/#97）
//   - authz：双 token 状态面（#119）——TokenHash 键空间单点、撤销黑名单
//     （token 级/用户级）、在线会话注册表（强踢），接口化存储 + 内存实现
//   - auth：认证流编排（#120/#121）——签发尾段、refresh 轮换防重放、登出
//     双 token 撤销、改密吊销钩子，错误分型 401/500 单点
//   - pwd：密码策略与改密陈旧判定（#121）——弱口令拒绝面、历史防复用
//     （fail-closed）、TokenStaleBefore 秒截断比较，纯 Go 零依赖
//
// 基础微工具（errors/stringx/timex/container 等）仍在 github.com/oekit/pkg。
package kitx
