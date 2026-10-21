# Changelog — oekit/kitx

由 oekit/pkg v0.10.0 拆分而来（uidgen、validator 两包）。所有 notable 变更记录如下。


## [v0.3.0] — 2026-10-21

- feat(uidgen)：补 ULID 原语——26 字符、字典序 = 时间序的字符串 ID（#17）
- `ULID()`：48 bit 毫秒时间戳 + 80 bit 熵，Crockford Base32 编码；字母表按 ASCII 升序，故字典序 == 时间序，可在 text 主键列上直接 range scan
- 同毫秒内进程内严格单调（熵逐个递增，80 bit 用尽则进位到下一毫秒）；时钟回拨时冻结在上次的毫秒继续递增熵，保证不出现更小的 ID
- `ULIDFromTime(t)`：按业务时间回填（熵随机，不混入单调序列）；`ParseULID(s)`：解回毫秒时间戳与 80 bit 熵，大小写不敏感
- 零第三方依赖（crypto/rand + 标准库位运算）；位布局与 oklog/ulid 逐位兼容（以其权威向量钉死）

## [v0.2.1] — 2026-10-19

- build: 矩阵内依赖地板对齐（align_floors 不动点）：pkg v0.11.0 → v0.15.1

## [v0.2.0] — 2026-10-18

### feat(hash)：非密码学哈希助手 `Md5Hex`/`Md5Bytes`（oekit/pkg#10）
- `Md5Hex(s)`（32 位小写 hex）/ `Md5Bytes(b)`（16 字节）——收编各业务仓手写的
  MD5 副本：缓存键生成（换哈希算法会使存量键批量失效，无法平滑升级 SHA-256）
  与短唯一 code（入库格式即契约）两类正当场景
- **格式稳定承诺**：算法与输出编码永不更换（存量键/码兼容是存在理由），
  测试与 ekit 时代手写实现逐字节互证
- ⚠️ 仅限非密码学场景（缓存键/幂等键/内容寻址），禁用于凭据/签名——密码学
  摘要用 pkg/encoding Sha256Hex。落位 kitx 而非恢复 pkg/encoding：pkg 2026-09-15
  治理轮移除弱哈希入口的决定保持不变，`kitx/hash` 的 import 路径即是
  「非密码学选型」的显式表达

## [v0.1.1] — 2026-10-17

- pkg 地板 v0.10.0 → v0.11.0

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
