package pwd

import (
	"context"
	"fmt"
	"time"
)

// TokenStaleBefore 令牌陈旧判定（#121 秒截断比较，本包的单点实现——
// authz.RevokedUser 的用户级判定复用同一份，两处各写一份比较正是
// #119/#121 要消灭的漂移形态）：
//
//	iat 严格早于 changedAt ⇒ 陈旧（true）。
//
// 两侧截断到秒再比较：JWT 的 iat 本就是秒粒度（签发写 Unix 秒），改密时间
// 常带亚秒（DB 时间戳），截断后比较避免亚秒边界把「改密后同一秒内新签的
// 令牌」误判陈旧（误判即全站踢下线，数据面故障不放大成 401 的同款取舍）。
// 同一秒不判陈旧——秒粒度语义的既定边界，godoc 钉明。
//
// changedAt 为 nil（无改密记录）⇒ 不陈旧。
func TokenStaleBefore(iat time.Time, changedAt *time.Time) bool {
	if changedAt == nil {
		return false
	}
	return iat.Truncate(time.Second).Before(changedAt.Truncate(time.Second))
}

// ApplyExpiryOnLogin 登录期密码过期判定（#121）：密码服役超过 days 天 ⇒
// 置 *mustChange = true 并调用 persist 落库（登录成功路径调用，强制引导改密）。
//
// 契约：
//   - days <= 0：未启用过期策略，no-op（nil）；
//   - mustChange 为 nil：调用方配置 bug，报普通 error（归 500，#115 同口径）；
//   - changedAt 为 nil：无改密记录，不判过期（创建时间口径由调用方折算后
//     传入——库层不猜「changedAt 缺省=注册时间」）；
//   - 未过期：不动 *mustChange（不清零——标记可能被其它路径（管理员强制）
//     置真，清零是 fail-open）；
//   - persist 失败：原样上抛（fail-closed：不吞错放行）；*mustChange 已置位
//     （内存态保留，是否重试落库由调用方决定）。
//
// 判定用 time.Now()（无时钟注入：days 以天计，亚秒边界无关语义；测试以
// 相对时刻构造）。
func ApplyExpiryOnLogin(ctx context.Context, days int, mustChange *bool, changedAt *time.Time, persist func(context.Context) error) error {
	if days <= 0 {
		return nil
	}
	if mustChange == nil {
		return fmt.Errorf("pwd: ApplyExpiryOnLogin 的 mustChange 不能为 nil")
	}
	if changedAt == nil {
		return nil
	}
	if !changedAt.Before(time.Now().AddDate(0, 0, -days)) {
		return nil
	}
	*mustChange = true
	if persist != nil {
		if err := persist(ctx); err != nil {
			return fmt.Errorf("pwd: 过期标记落库失败（fail-closed）: %w", err)
		}
	}
	return nil
}
