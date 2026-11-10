## [v0.7.0] — 2026-11-11

- feat(jwt): 签发侧新增 `WithAudienceClaims`——aud 的签发出口（#117）：signPayload 写入 aud（单受众 string / 多受众 []string 双形态，与 claimsFromMap 解析面对称），「签发→解析」的 aud 闭环打通（与 WithAudience fail-closed（#66）对接），多受众部署不再被迫手搓 payload；`Manager.Refresh` 继承面同步带上 aud（轮换产物仍可过 WithAudience 校验；nbf 不随轮换继承——生效窗口随新 exp/iat 重开）；WithClaim 保留声明报错指引补 WithAudienceClaims 出口（#71 注入面防护不动）；选项入参 slices.Clone 拷贝，空串受众 fail-fast panic（#65 同款纪律）
- fix(validator): `ValidationError` 的 errors 切片双向共享切断（#116，core#80 同构换仓复发）——`NewFieldValidationError` 构造期 slices.Clone 拷贝入参、`Errors()` 返回副本，错误值不可变契约补齐：调用方事后改写入参/返回值不再污染 Error()/Map()/String()，跨 goroutine 异步上报的数据竞争面一并关闭
- fix(validator): Validate/ValidateVar(VarNamed) 上游引擎 panic 就地转 error + ERROR 日志（#115）——bool/struct 字段挂 min/max/len 等「tag 与字段 Kind 不匹配」形态不再炸穿请求链，#94 三道闸补上校验路径闸（「panic 不出网」承诺全覆盖）；tag 误用按普通 error 上抛（handler 层 500），不归 ValidationError 400——服务端结构体定义 bug 归 400 会让排障指错方向
- refactor(jwt): IssuePair/Refresh 的 ttl 非正判断改写 `min` 内建（Go 1.21+，与「任一非正即拒」等价，语义不变）
- 现代特性：defer+recover 转 error（#115）、slices.Clone（#116 双向拷贝、#117 选项入参拷贝）、min（ttl 判断）；errors.Join/max 本批无贴合处未强用
- 版本号取 v0.7.0 而非 v0.6.3：#117 新增公开 API `WithAudienceClaims`（SignOption），0.x 阶段 minor 承载加法 API

关联问题单：kitx#115、kitx#116、kitx#117。

## [v0.6.2] — 2026-11-10

- - build: 依赖地板对齐（第二轮发版后 floor sync，无代码变更）

## [v0.6.1] — 2026-11-10

- - build: 依赖地板对齐（floor sync，无代码变更）

## [v0.6.0] — 2026-11-10

- - fix(validator): RegisterValidation nil 规则注册期返回 ErrNilValidationFunc、受限 tag panic 转校验失败、规则 panic 就地隔离（#94）
- - feat(jwt): WithExpectedIssuer——iss 严格相等且必须存在的 fail-closed 校验（#95）
- - fix(jwt): MarshalKeyPairPEM 缺 Public 对称返回 error（#96）
- - feat(jwt): Manager/IssuePair/ParseTyped/Refresh 双令牌对原语——token_type 入 reservedClaims，轮换继承会话声明（#97）

关联问题单：kitx#94、kitx#95、kitx#96、kitx#97。

## [v0.5.0] — 2026-11-09

- feat(uidgen): `RandomHexE`/`RandomStringE` error 返回变体（kitx#87）——crypto/rand 读取失败这一**运行期环境故障**从 panic 改为返回 error：请求路径（nonce/token/上传会话 ID）可就地降级，下游不必再因「没有 error 出口」而 `_, _ = rand.Read(b)` 吞错发出弱值或手搓 make+rand.Read+hex；入参防呆不变（非法入参仍 panic，对齐 #50 哲学）
- feat(uidgen): `RandomHexFrom`/`RandomStringFrom(io.Reader)` 显式随机源变体（kitx#87）——专供测试注入确定性/必然失败随机源，nil reader 视为非法入参 panic；取样经共享核心 `sampleRunes` 与 E 版共用同一份实现（无第二份 256%len 偏差修复代码）；读取语义 io.ReadFull，注入短读 reader 循环读满
- **BREAKING** fix(uidgen): `RandomString(alphabet, n<=0)` 从静默空串改为 panic（kitx#88）——与 #50 对 `RandomHex` 的修法同口径：空串密钥是最危险的缺省（空 HMAC key 可被任意伪造、空 token 落库与「无 token」不可区分）
- **BREAKING** fix(uidgen): `RandomString` 采样从字节口径改为 rune 口径（kitx#89）——多字节 alphabet 产出恰 n 个字符的合法 UTF-8（旧口径产孤立带头/续字节，进 JSON/DB utf8 列/日志即损坏）；`>256` panic 判据同步改按字符数计（300 字节的 100 个「字」不再被 #52 判据误杀）
- feat(jwt): HS256 对称形态 `NewSymmetric`/`SymmetricSigner`/`ParseSymmetric`——与 RS256 共享同一套选项与校验语义，入口绑定算法白名单关死 alg 混淆（kitx#86）

关联问题单：kitx#86、kitx#87、kitx#88、kitx#89。

## [v0.4.3] — 2026-11-08

- build: 依赖地板对齐——本版把 oekit 依赖地板抬到各依赖当前最新已发布版本（matrix-tools/scripts/align_floors.py 维护轮）

## [v0.4.2] — 2026-11-07

- feat(jwt): Sign 新增 WithIssuedAt/WithNow——iat 可注入、exp/iat 同钟源（#64）
- fix(jwt): WithTTL(0) 从静默产出无 exp 令牌改为 panic + 显式 WithNoExpiry（BREAKING）（#65）
- feat(jwt): Parse 新增 WithAudience——aud 校验（any-of/缺 aud fail-closed/不设置不校验）（#66）
- fix(jwt): Parse 对类型异常的注册声明 fail-closed 拒绝——RFC 7519 违规令牌不再静默归零（#67）
- fix(jwt): Parse 错误链保留（%w: %w）——过期与伪造令牌可 errors.Is 分流（#70）
- fix(jwt): Sign 拒绝 WithClaim 注入 exp/iss/iat 等保留注册声明——令牌声明注入面关闭（#71）
- fix(uidgen): Snowflake 时钟回拨策略——容忍上限等待 + 超限进位生成 + OnClockBack 回调，NTP 大幅回拨不再卡死全进程（#72）
- fix(validator): min/max 校验消息按字段类型区分——数值边界不再误写 "length must be"（#73）

关联问题单：kitx#64、kitx#65、kitx#66、kitx#67、kitx#70、kitx#71、kitx#72、kitx#73。

## [v0.4.1] — 2026-11-06

- fix(uidgen): alphabet 超限死循环防呆 + epoch doc 修正（kitx#52 #53）

关联问题单：kitx#52、kitx#53。

## [v0.4.0] — 2026-11-06

- feat: 新增 jwt 子包——RS256 JWT 签发与校验：header 只含 {"alg":"RS256"} 不带 typ（与 Nimbus/既有消费方互通）、业务声明 WithClaim 平铺 / Claims.Extra 收集、PEM 密钥对（PKCS#1/PKCS#8 私钥，PKIX/PKCS#1/X.509 证书公钥）。来源：kuboard-go JWT 契约上移（matrix 决策 U2）

## [v0.3.6] — 2026-11-06

- build: 矩阵依赖地板对齐（维护轮 #233）

## [v0.3.5] — 2026-11-05

- **BREAKING** fix(uidgen): `RandomHex(nBytes<=0)` 从静默返回空串改为 **panic**（[#50](https://github.com/oekit/kitx/issues/50)）——对标识符场景「非法长度=调用方 bug」，对 doc 同样点名的密钥/凭据场景（webhook secret、HMAC key、API token）静默空串是**最危险的缺省**：名义生成了、实际是空钥匙，空串做 HMAC key / API token 落库后患无穷，而宿主（bianque `deploy.GenerateSecret`）被迫自包 `nBytes<=0` 特判。与同包 `RandomString` 空 alphabet panic 的防呆哲学对齐（非法入参启动即暴露好过静默降级）；panic 消息点名「空串密钥是最危险的缺省」。迁移：长度来自配置面的调用方在构造期校验；矩阵全仓 grep 核过无调用方依赖旧「静默空串」行为

关联问题单：kitx#50。

# Changelog — oekit/kitx

由 oekit/pkg v0.10.0 拆分而来（uidgen、validator 两包）。所有 notable 变更记录如下。


## [v0.3.4] — 2026-11-02

- build: 矩阵内依赖地板 `pkg` v0.31.0 → v0.31.1（维护轮全量对齐；本版不含 API 变更）

## [v0.3.3] — 2026-10-28

- feat(validator): 新增 `ValidateVarNamed(field, fieldName, tag)`——单变量校验此前**丢掉字段名**（底层 go-playground/validator 的 Var 路径不返回字段名）⇒ 错误消息是 " is required"（前导空格、没有主语），`ValidationError.Map()` 还多出一个空字符串键 ⇒ 直接喂 JSON 响应会得到 `{"": " is required"}`。走可选接口 `VarValidatorWithName`（不给 `Validator` 接口加方法，仓外自定义实现不受影响）；无名路径用兜底主语 "value"，结构体校验路径不变

## [v0.3.2] — 2026-10-28

- fix(validator): `SetDefault(nil)` 把 nil 接口存进全局 ⇒ `Default()` 返回 nil ⇒ 后续每一次 `Default().Validate(obj)` 都是**空指针崩溃**，而且崩在调用方、栈里只有 `validator.Default().Validate` 这一行，完全看不出根因是这里存了个 nil。改为**直接 panic**（快速失败比静默埋雷好）；`Default()` 另加兜底——atomic 指针为空时返回一个可用的默认验证器，而不是在解引用处崩

## [v0.3.1] — 2026-10-23

- build: 矩阵内依赖地板对齐（align_floors 不动点）：pkg v0.15.1 → v0.22.0（#26）

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
