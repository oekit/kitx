// Package pwd 提供密码策略与改密陈旧判定原语（#121）：最小长度/复杂度/常见
// 弱口令拒绝面、历史防复用（fail-closed）、登录期过期轮换判定、令牌陈旧
// 秒截断比较——纯 Go 零依赖。
//
// #121 的缺口：最小长度、历史防复用、过期轮换、改密后旧会话失效是账号体系
// 标配，下游（zeus 3 服务）同构手搓 pwdpolicy/pwdfresh 两包；其中
// 「fail-closed 的安全取舍」正该由库统一：
//
//   - 历史查询失败 ≠ 放行（HistoryCheck 契约：Fetch/Match 出错原样上抛，
//     绝不降级成「没查到历史 ⇒ 新密码可用」）；
//   - 秒截断比较（TokenStaleBefore）：iat 与改密时间同秒不判陈旧——JWT iat
//     本就是秒粒度，截断后比较避免时区/亚秒边界把「改密后新签的令牌」误判
//     陈旧（数据面故障也不放大成 401 全站踢下线）；
//   - 策略违规与服务端配置 bug 分型（#115 同口径）：违规是 Violation（Unwrap
//     为 BizError 400，middleware.Fail 自动映射 400），策略配置非法是普通
//     error（归 500——配置 bug 归 400 会让排障指错方向）。
//
// 弱口令拒绝面是「内嵌常见弱口令表 + 轻量 leet 归一 + 结构性弱模式」，
// 非 zxcvbn 级熵评估——纯 Go 零依赖是本包的边界（哈希比对器 Matcher 由调用
// 方注入，典型 bcrypt.CompareHashAndPassword 包装，库层不绑哈希算法）。
//
// 改密陈旧吊销（改密后旧 token 失效）的编排钩子在 kitx/auth.RevokeUser——
// 落到 kitx/authz 的用户级撤销黑名单；本包的 TokenStaleBefore 是其判定口径
// 的单点实现（authz.RevokedUser 复用同一份）。
package pwd
