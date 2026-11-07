package uidgen

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// snowflakeEpoch 是 Snowflake ID 使用的 epoch 起点（毫秒）.
// 2025-01-01 00:00:00 UTC（1735689600000）。改常量会破坏存量 ID 的
// ExtractSnowflakeTime 解析，只能改注释对齐事实；距溢出余量约 68 年.
// 区别于旧式 ID 的 epoch（2024-01-01）：Snowflake 提取时间用 ExtractSnowflakeTime.
const snowflakeEpoch int64 = 1735689600000

// defaultClockBackTolerance 是缺省的时钟回拨容忍上限（#72）：回拨不超过它时
// 维持既有行为——持锁等待时钟追平（最坏等满容忍上限）；超过它则不再等待，
// 转进位生成。5s 覆盖 NTP 常规步进与小幅校时，同时把「等时钟追平」的最坏
// 阻塞从无限长压到 5s。
const defaultClockBackTolerance = 5 * time.Second

// Snowflake 是 singleton 模式的 Snowflake ID 生成器.
//
// Bit 布局（bit 63 → 0）：
//
//	[1 sign | 41 ts | 10 machine | 12 sequence]
//
// = ~69 years × 1024 machines × 4096 IDs/ms per machine.
//
// 区别于旧式 ID 生成：
//   - Singleton 模式，业务侧直接调 SnowflakeID() 拿下一个 int64 ID.
//   - 时钟回拨不无限忙等（#72）：容忍上限内（缺省 5s）持锁等时钟追平；
//     超限转进位生成（以回拨前基准继续发号），可注册 WithOnClockBack 告警.
//   - API 极简：InitSnowflake + SnowflakeID，不暴露 mu / sequence / lastTS.
//
// 并发模型：
//   - InitSnowflake 用 atomic.Pointer CAS 保证 "只 init 一次" + "成功后立刻可见".
//   - SnowflakeID() auto-init 路径在 CAS 失败时回退到 Load()，避免 nil deref.
//   - next() 持单 mu 串行：临界区短（同 ms 仅几次算术，跨 ms 持锁等下 ms 最坏 1ms）.
//
// Reference: https://github.com/twitter-archive/snowflake (Twitter, 2010)
type Snowflake struct {
	epoch     int64 // 自定义 epoch，毫秒
	machineID int64 // 0..maxWorker，注入不可变
	mu        sync.Mutex
	lastTS    int64
	sequence  int64
	// clockBackTolerance 时钟回拨容忍上限；onClockBack 是超限回拨的通报回调
	//（进位生成模式启动时触发，每轮回拨一次，持锁同步调用）；synthetic 标记
	// 当前处于进位生成模式（真实时钟落后于 lastTS，以 lastTS 继续发号）。
	clockBackTolerance time.Duration
	onClockBack        func(back time.Duration)
	synthetic          bool
}

// SnowflakeOption 是 Snowflake 生成器的配置选项（#72），经 InitSnowflakeWith
// 注入全局单例。
type SnowflakeOption func(*Snowflake)

// WithClockBackTolerance 设置时钟回拨容忍上限 d（缺省 5s，#72）：回拨 ≤ d 时
// 维持既有行为——持锁等待时钟追平（最坏等满 d）；回拨 > d 时不再等待，转
// 进位生成。d ≤ 0 表示任何回拨都直接进位生成。
func WithClockBackTolerance(d time.Duration) SnowflakeOption {
	return func(s *Snowflake) {
		if d < 0 {
			d = 0
		}
		s.clockBackTolerance = d
	}
}

// WithOnClockBack 注册大幅时钟回拨通报回调（#72）：回拨幅度超过容忍上限时，
// 生成器放弃等待、转进位生成——ID 时间戳领先真实时钟直到追平，本回调以实际
// 回拨幅度 back 触发，每轮回拨（从进入进位生成到真实时钟追平）只触发一次。
// 未注册时缺省 slog.Warn。
//
// 回调在生成器持锁状态下同步调用，必须快速返回（记数/投递告警即可）：
// 阻塞会卡住全进程的 ID 生成；再调 SnowflakeID/InitSnowflake 会死锁。
func WithOnClockBack(fn func(back time.Duration)) SnowflakeOption {
	return func(s *Snowflake) { s.onClockBack = fn }
}

// defaultSnowflake 用 atomic.Pointer 而不是 mutex+struct 保护：
//
//   - CAS 一次完成 "init 标记 + 指针可见" 两件事，对其他 goroutine 立刻可见.
//   - Load() 无锁读，hot path 零开销.
//   - resetForTest 直接 Store(nil)，单步原子，无需持业务锁.
var defaultSnowflake atomic.Pointer[Snowflake]

// InitSnowflake 初始化全局 Snowflake singleton（缺省容忍上限 5s，无回拨回调）.
// machineID 必须在 [0, 1023] 范围. 多次调用：第一次生效，后续返错（防止误用）.
//
// 并发安全：CAS(nil -> s) 失败表示已初始化，Load() 拿到的是上次成功的实例.
func InitSnowflake(machineID int64) error {
	return InitSnowflakeWith(machineID)
}

// InitSnowflakeWith 带选项初始化全局 Snowflake singleton（#72）：
// WithClockBackTolerance 调时钟回拨容忍上限、WithOnClockBack 注册大幅回拨
// 通报回调。machineID 范围与多次调用规则同 InitSnowflake.
func InitSnowflakeWith(machineID int64, opts ...SnowflakeOption) error {
	if machineID < 0 || machineID > maxWorker {
		return errors.New("uidgen: machineID must be in [0, 1023]")
	}
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          machineID,
		clockBackTolerance: defaultClockBackTolerance,
	}
	for _, opt := range opts {
		opt(s)
	}
	if !defaultSnowflake.CompareAndSwap(nil, s) {
		return errors.New("uidgen: snowflake already initialized")
	}
	return nil
}

// InitSnowflakeFromEnv 从 MACHINE_ID env 读 machineID，解析失败兜底 0.
// 单进程 dev / 测试默认 0 够用；生产必须显式注入（e.g. docker-compose 配 0/1/2）.
func InitSnowflakeFromEnv() error {
	raw := os.Getenv("MACHINE_ID")
	if raw == "" {
		slog.Warn("uidgen: MACHINE_ID not set, defaulting to 0; set MACHINE_ID in production to avoid ID collisions")
		return InitSnowflake(0)
	}
	mid, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		slog.Warn("uidgen: invalid MACHINE_ID, defaulting to 0", "value", raw, "err", err)
		return InitSnowflake(0)
	}
	return InitSnowflake(mid)
}

// SnowflakeID 拿下一个 int64 ID. 未 InitSnowflake 时自动以 machineID=0 初始化.
//
// 并发说明：auto-init 路径在多 goroutine 同时首次调用时，CAS 失败的 goroutine
// 会回退到 Load() 读已 init 的实例，保证不会 nil deref.
//
// 时钟回拨（#72）：回拨在容忍上限内（缺省 5s，InitSnowflakeWith +
// WithClockBackTolerance 可调）时持锁有界等待时钟追平；超限（如 NTP 大幅
// 回拨）转进位生成——以回拨前基准继续发号，不再阻塞，ID 时间戳领先真实
// 时钟直到追平（ExtractSnowflakeTime 读到的是合成时刻）。大幅回拨可用
// WithOnClockBack 注册回调接告警.
func SnowflakeID() int64 {
	s := defaultSnowflake.Load()
	if s == nil {
		// auto-init machineID=0. InitSnowflake(0) 不可能因 machineID 范围失败
		// （0 在 [0,1023] 内）；CAS 失败仅表示已被并发初始化。两种情况下
		// 重新 Load 都必非 nil。
		if err := InitSnowflake(0); err != nil {
			slog.Debug("uidgen: snowflake auto-init raced, using winner's instance", "err", err)
		}
		s = defaultSnowflake.Load()
	}
	return s.next()
}

// SnowflakeMachineID 返当前 init 用的 machine ID，未初始化返 -1，测试用.
func SnowflakeMachineID() int64 {
	s := defaultSnowflake.Load()
	if s == nil {
		return -1
	}
	return s.machineID
}

func (s *Snowflake) next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		now := time.Now().UnixMilli()

		if now < s.lastTS {
			switch {
			case s.synthetic:
				// 已在进位生成模式：继续以 lastTS 为基准发号，直到真实时钟追平
				now = s.lastTS
			case time.Duration(s.lastTS-now)*time.Millisecond <= s.clockBackTolerance:
				// 容忍度内的小幅回拨：维持既有行为——持锁等时钟追平
				//（最坏等满容忍上限，不再无限期）
				time.Sleep(time.Millisecond)
				continue
			default:
				// 超容忍度的大幅回拨（如 NTP 校时回拨一小时）：不再无限持锁
				// 忙等——转进位生成，以 lastTS 为基准继续发号。ID 时间戳领先
				// 真实时钟 back，直到真实时钟追平；期间 ExtractSnowflakeTime
				// 读到的是合成时刻。每轮回拨只通报一次.
				back := time.Duration(s.lastTS-now) * time.Millisecond
				s.synthetic = true
				s.notifyClockBack(back)
				now = s.lastTS
			}
		} else if s.synthetic {
			// 真实时钟已追平（≥ lastTS），退出进位生成模式
			s.synthetic = false
		}

		if now == s.lastTS {
			// 同 ms 内：递增 sequence
			s.sequence = (s.sequence + 1) & sequenceMask
			if s.sequence == 0 {
				if time.Now().UnixMilli() < s.lastTS {
					// 进位生成模式下的 sequence 用尽：合成推进 1ms——
					// 不能等真实时钟，那是 #72 要消灭的无限等待
					s.lastTS++
				} else {
					// 常规 sequence 用完（4096/ms），必须等下一 ms
					// 持锁等：不能释放，否则下一个 caller 会从 0 递增
					// 拿到 seq=1 但 seq=1 本 ms 已经发过，撞号.
					for time.Now().UnixMilli() == s.lastTS {
						time.Sleep(time.Microsecond * 100)
					}
				}
				continue
			}
			return (now-s.epoch)<<timestampShift | (s.machineID << workerShift) | s.sequence
		}

		// now > last：新 ms
		s.lastTS = now
		s.sequence = 0
		return (now-s.epoch)<<timestampShift | (s.machineID << workerShift) | s.sequence
	}
}

// notifyClockBack 通报一次超限时钟回拨（#72）：优先用 WithOnClockBack 注册的
// 回调，未注册时 slog.Warn 兜底。调用方（next）持锁中同步调用.
func (s *Snowflake) notifyClockBack(back time.Duration) {
	if s.onClockBack != nil {
		s.onClockBack(back)
		return
	}
	slog.Warn("uidgen: snowflake clock moved back beyond tolerance, carry-forward generation engaged (ID timestamps run ahead of wall clock until it catches up)",
		"back", back, "tolerance", s.clockBackTolerance)
}

// ExtractSnowflakeTime 从 Snowflake ID 中提取生成时间.
// 注意：与 ExtractTime 不可混用——epoch 不同（2025 vs 2024）.
func ExtractSnowflakeTime(id int64) time.Time {
	ts := (id >> timestampShift) + snowflakeEpoch
	return time.UnixMilli(ts)
}

// ExtractSnowflakeMachineID 从 Snowflake ID 中提取 machineID.
func ExtractSnowflakeMachineID(id int64) int64 {
	return (id >> workerShift) & maxWorker
}

// ExtractSnowflakeSequence 从 Snowflake ID 中提取 sequence.
func ExtractSnowflakeSequence(id int64) int64 {
	return id & sequenceMask
}

// resetForTest 仅供测试重置全局状态. 业务代码不要调.
// Store(nil) 是单步原子操作，无需持业务锁——next() 持 mu 保证临界区不撕裂.
func resetForTest() {
	defaultSnowflake.Store(nil)
}
