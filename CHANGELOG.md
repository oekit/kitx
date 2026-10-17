# Changelog — oekit/kitx

由 oekit/pkg v0.10.0 拆分而来（uidgen、validator 两包）。所有 notable 变更记录如下。


## [v0.1.0] — 2026-10-17

- **feat(uidgen)**: 初始版本——自 `oekit/pkg` 拆出。Snowflake（全局单例 +
  `ExtractTime`/`ExtractWorkerID`/`ExtractSequence` 旧式提取 + `ExtractSnowflake*`）、
  UUID 系列、`RandomHex`/`RandomString`（拒绝采样）原样迁移
- **refactor(uidgen)**: UUID 改为标准库手写 RFC 4122 v4（crypto/rand +
  version/variant 位，`crypto/rand.Read` 失败 panic 与 `RandomHex` 同款），
  **去除 `github.com/google/uuid` 依赖**——对外 5 个函数签名与输出语义
  （小写、连字符规则、截取行为）逐字节不变
- **feat(validator)**: go-playground/validator v10.30.1 接口化门面——`Validator`
  接口 + `PlaygroundValidator`（json tag 字段名 + `formatMessage` 内置英文提示）、
  `ValidationError`（Unwrap 为 `pkg/errors` BizError 400，错误映射链行为不变）、
  `SetDefault`/`Default`（atomic.Pointer）
- build: go 1.24.0；CI 工具链钉 1.24 实测下限；依赖 `github.com/oekit/pkg`
  （仅 errors/BizError 链路，pkg v0.10.0 起为零第三方模块）+
  go-playground 链（go1.24 兼容版：x/crypto v0.48.0 / x/text v0.34.0 / x/sys v0.41.0）
