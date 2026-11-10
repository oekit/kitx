// Package auth 提供认证流编排原语（#120）：access+refresh 签发尾段、refresh
// 轮换（旧令牌防重放）、登出双 token 撤销、改密陈旧吊销钩子（#121）——安全
// 不变式的单点实现，基于 kitx/jwt（签发/校验）与 kitx/authz（状态面）。
//
// #120 的缺口：认证流的编排语义是安全不变式——轮换必踢旧会话、GetByID 错误
// 分型 401/500、TouchLogin 尽力而为、登出双 token 撤销——下游（zeus 3 认证
// 服务）「逐字同源」各持一份后**实际漂移**（错误映射不同、旧会话清理语义不
// 同），只能在自己仓内先收敛。本包把编排语义收进库层，下游只留仓储适配器
// （UserRepo 实现），不再各自维护一份轮换时序。
//
// 核心不变式（godoc 契约，测试钉死）：
//
//   - 轮换必踢旧会话，且旧 refresh **单次使用**：RotateRefresh 以
//     SessionRegistry.Kick 的原子认领拍板——并发轮换同一 refresh 恰有一方
//     成功，败方按 ErrReplayed 拒绝（401）；旧 refresh 落黑名单，二次使用
//     恒被拒（ErrReplayed，可 errors.Is 分流告警）。
//   - 错误分型 401/500：ErrUnauthorized（BizError 401，middleware.Fail 自动
//     映射）承载全部 401 语义（凭据无效/已吊销/会话不在/查无此人）；存储/仓储
//     故障原样上抛（归 500）——既不放行（fail-open），也不放大成 401 全站
//     踢下线。
//   - TouchLogin 尽力而为：失败只记日志不阻断轮换（登录活跃度是弱信号）。
//   - 登出撤销覆盖双 token：会话下线（双 hash 拉黑 + 删键）+ 呈现令牌直接
//     拉黑，幂等可重。
//
// 三件套咬合（#119/#120/#121）：本包消费 #119 状态面（authz.Revoker /
// SessionRegistry），#121 的改密吊销钩子（RevokeUser）落到 #119 的用户级
// 撤销黑名单 + 全会话强踢；陈旧判定口径单点在 pwd.TokenStaleBefore。
package auth
