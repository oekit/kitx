# kitx

> 标识与校验——Snowflake / UUID / 随机串 + go-playground/validator 门面

> 🌐 项目主页：**https://oekit.github.io/** · 名称由来：**O**pen **E**asy **Kit**（开源 · 易用 · 工具集合）
> 🤖 AI Agent：本仓规范与硬规则见 [AGENTS.md](AGENTS.md)；机器可读索引见 [llms.txt](https://oekit.github.io/llms.txt)（接口签名以源码为准）。

## 安装

```bash
go get github.com/oekit/kitx@v0.1.0
```

## 这个仓库做什么

`kitx` 是 **标识与校验** 工具仓（自 `oekit/pkg` v0.10.0 拆出，pkg 本体自此零第三方依赖）：

- `uidgen` —— 分布式唯一 ID 与随机串：Snowflake（全局单例 + Extract 元数据提取）、
  RFC 4122 v4 UUID（**标准库手写，零第三方依赖**，语义与 google/uuid 对齐）、
  crypto/rand 随机串（RandomHex / 拒绝采样 RandomString，无 mod 偏置）
- `validator` —— go-playground/validator 的接口化门面：struct tag 校验、
  自定义规则注册、`ValidationError`（`Unwrap` 为 `pkg/errors` BizError 400，
  `middleware.Fail` 自动映射 HTTP 400）

## 组成

| 包 | import 路径 | 做什么 |
|---|---|---|
| `uidgen` | `github.com/oekit/kitx/uidgen` | `InitSnowflake(machineID)` / `SnowflakeID()`（不返错，auto-init 兜底）+ `ExtractSnowflake*` 元数据；`UUID`/`ShortUUID`/`UUIDToUpper`/`ShortUUIDToUpper`/`UUIDWithHyphen`（手写 v4，零第三方）；`RandomHex(n)` / `RandomString(alphabet, n)`（crypto/rand，拒绝采样） |
| `validator` | `github.com/oekit/kitx/validator` | `Validate(obj)` / `ValidateVar(field, tag)`（struct tag）；`RegisterValidation`（⚠️ 仅限 init 阶段，底层注册非并发安全）；`ValidationError.Errors()/Map()/Len()` 结构化字段错误；`SetDefault`/`Default` 可替换实现（atomic.Pointer 并发安全） |

## 快速使用

```go
import (
    "github.com/oekit/kitx/uidgen"
    "github.com/oekit/kitx/validator"
)

// 唯一 ID
uidgen.InitSnowflake(7)          // 一次性初始化, machineID ∈ [0, 1023]
id := uidgen.SnowflakeID()       // int64
uid := uidgen.UUID()             // 32 位无连字符 v4 UUID
secret := uidgen.RandomHex(32)   // 64 字符高熵随机串

// 参数校验
type CreateUserReq struct {
    Name  string `json:"name" validate:"required,min=1,max=100"`
    Email string `json:"email" validate:"required,email"`
}
if err := validator.Validate(&req); err != nil {
    var ve *validator.ValidationError
    if errors.As(err, &ve) {
        // ve.Map() → field→message，直接喂 JSON 响应
    }
}
```

## 设计说明

- **为什么 validator 依赖 `pkg/errors`**：`ValidationError.Unwrap` 返回
  BizError(400)，让 `middleware.Fail` / `gormx` / `kitex bridge` 的错误映射链
  把参数错误归为 HTTP 400 而非 500——这是行为契约，不能断。
- **为什么 UUID 手写**：v4 只需 16 随机字节 + version/variant 位，引整个
  google/uuid（解析/各版本/marshal）为单一生成场景不划算，且少一个
  dependabot 升级通道。
