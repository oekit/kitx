// Package authz 提供双 token 的**状态面**原语（#119）：撤销黑名单（token 级 /
// 用户级）与在线会话注册表（设备/会话维度登记、枚举、强踢），与 kitx/jwt 的
// 校验面（ParseTyped 等）组合消费——jwt 只管「令牌是不是我签的、过没过期」，
// 本包回答「这枚令牌还能不能用」「某用户在哪些设备在线」「如何把他踢下线」。
//
// #119 的缺口：kitx/jwt pair.go 明文把撤销黑名单等有状态部分留在平台层，下游
// （zeus 4 服务）只能手搓两份拷贝靠注释对齐哈希口径，漂移即强踢失效。本包把
// 「必须单点」的键空间/哈希约定收进库层：
//
//   - TokenHash 是键空间唯一产出口（sha256hex），黑名单/会话注册表的键全部
//     由此派生，跨服务不再各写一份；
//   - Revoker / SessionRegistry 接口化存储面（#119 建议形态）：内存实现
//     MemRevoker / MemRegistry 随包交付（单实例进程内部署与测试替身双用），
//     Redis 等持久实现由下游按同一契约落地（键前缀可配、TTL=refresh 剩余
//     寿命的约定写在各方法契约里）。
//
// 撤销语义两层：
//
//   - token 级：Revoke(hash, remaining)——单枚令牌拉黑，条目 TTL=令牌剩余
//     寿命（过期自然出清，过期令牌本就被 exp 拒绝）；
//   - 用户级：RevokeUser(userID, at)——截断点，at 之前签发的全部令牌判陈旧
//     （#121 改密陈旧吊销的落地口）。判定口径单点在 pwd.TokenStaleBefore
//     （秒截断比较），本包复用之，两处比较不各写一份。
//
// 会话语义（SessionRegistry）：Register 登记（TTL=refresh 剩余寿命）、
// ListByUser 管理端枚举、Kick 单会话强踢（**双 hash 拉黑 + 删键**，原子认领
// 语义供 refresh 轮换防重放拍板）、KickUser 全会话强踢。编排层（kitx/auth）
// 在此之上交付签发尾段/轮换/登出/改密吊销的单点语义。
//
// 并发契约：MemRevoker / MemRegistry 全方法并发安全（共享状态 mutex 保护），
// 不启动后台 goroutine——过期条目读判即视为不在，Sweep 可手动清扫。
package authz
