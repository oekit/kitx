// Package uidgen 提供分布式唯一 ID 生成器.
//
// 推荐使用 Snowflake（全局单例 + 极简 API）：
//
//	uidgen.InitSnowflake(7)                  // 一次性初始化, machineID ∈ [0, 1023]
//	id := uidgen.SnowflakeID()               // int64, 不返错, auto-init 兜底
//	uidgen.ExtractSnowflakeTime(id)          // epoch = 2026-01-01
//	uidgen.ExtractSnowflakeMachineID(id)
//	uidgen.ExtractSnowflakeSequence(id)
//
// Extract 函数（epoch = 2024-01-01）用于从旧式 ID 中提取元数据：
//
//	uidgen.ExtractTime(id)
//	uidgen.ExtractWorkerID(id)
//	uidgen.ExtractSequence(id)
//
// UUID 系列（与 Snowflake 无关）见 uuid.go.
//
// ULID 系列（26 字符，字典序 == 时间序）见 ulid.go——面向「文本主键 +
// 按 ID 做时间序 range scan」的场景：
//
//	id := uidgen.ULID()                       // 26 字符，同毫秒内严格递增
//	uidgen.ULIDFromTime(t)                   // 指定时间戳（按业务时间回填）
//	ts, entropy, err := uidgen.ParseULID(id)  // 解回时间戳与 80 bit 熵
package uidgen
