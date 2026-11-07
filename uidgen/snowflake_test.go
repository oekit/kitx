package uidgen

import (
	"sync"
	"testing"
	"time"
)

func TestInitSnowflake(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(0); err != nil {
		t.Fatalf("first init: %v", err)
	}
	// 第二次 init 必须失败
	if err := InitSnowflake(1); err == nil {
		t.Error("expected error on second init")
	}
}

func TestInitSnowflake_OutOfRange(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(-1); err == nil {
		t.Error("expected error for negative machineID")
	}
	if err := InitSnowflake(1024); err == nil {
		t.Error("expected error for machineID > 1023")
	}
	// 边界值必须 OK
	if err := InitSnowflake(0); err != nil {
		t.Errorf("machineID=0 should be valid: %v", err)
	}
	resetForTest()
	if err := InitSnowflake(1023); err != nil {
		t.Errorf("machineID=1023 should be valid: %v", err)
	}
}

func TestInitSnowflakeFromEnv(t *testing.T) {
	t.Run("empty falls back to 0", func(t *testing.T) {
		resetForTest()
		t.Setenv("MACHINE_ID", "")
		if err := InitSnowflakeFromEnv(); err != nil {
			t.Fatalf("init: %v", err)
		}
		if got := SnowflakeMachineID(); got != 0 {
			t.Errorf("expected machineID 0, got %d", got)
		}
	})

	t.Run("valid value", func(t *testing.T) {
		resetForTest()
		t.Setenv("MACHINE_ID", "5")
		if err := InitSnowflakeFromEnv(); err != nil {
			t.Fatalf("init: %v", err)
		}
		if got := SnowflakeMachineID(); got != 5 {
			t.Errorf("expected machineID 5, got %d", got)
		}
	})

	t.Run("invalid value falls back to 0", func(t *testing.T) {
		resetForTest()
		t.Setenv("MACHINE_ID", "not-a-number")
		if err := InitSnowflakeFromEnv(); err != nil {
			t.Fatalf("init: %v", err)
		}
		if got := SnowflakeMachineID(); got != 0 {
			t.Errorf("expected fallback machineID 0, got %d", got)
		}
	})

	t.Run("out-of-range value rejected", func(t *testing.T) {
		resetForTest()
		t.Setenv("MACHINE_ID", "9999")
		if err := InitSnowflakeFromEnv(); err == nil {
			t.Error("expected error for out-of-range MACHINE_ID")
		}
	})
}

func TestSnowflakeID_Basic(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(7); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	id := SnowflakeID()
	after := time.Now()

	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	// ID 里的时间戳应在 [before, after] 之间（提取后比对）
	ts := ExtractSnowflakeTime(id)
	if ts.Before(before.Truncate(time.Millisecond)) || ts.After(after.Add(time.Millisecond)) {
		t.Errorf("extracted time %v out of expected range [%v, %v]", ts, before, after)
	}
}

func TestSnowflakeID_AutoInit(t *testing.T) {
	resetForTest()
	defer resetForTest()
	// 不调 Init，直接用，应自动以 machineID=0 初始化
	id := SnowflakeID()
	if id <= 0 {
		t.Errorf("expected positive ID after auto-init, got %d", id)
	}
	if got := SnowflakeMachineID(); got != 0 {
		t.Errorf("auto-init should use machineID 0, got %d", got)
	}
}

func TestSnowflakeID_Uniqueness(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(7); err != nil {
		t.Fatal(err)
	}

	seen := make(map[int64]struct{}, 10000)
	for i := 0; i < 10000; i++ {
		id := SnowflakeID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID: %d", id)
		}
		seen[id] = struct{}{}
	}
}

func TestSnowflakeID_Concurrent(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(7); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := make(map[int64]struct{})
	var wg sync.WaitGroup

	const goroutines = 100
	const perGoroutine = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				id := SnowflakeID()
				mu.Lock()
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate ID: %d", id)
				}
				seen[id] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got := len(seen); got != goroutines*perGoroutine {
		t.Errorf("expected %d unique IDs, got %d", goroutines*perGoroutine, got)
	}
}

func TestExtractSnowflakeFields(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(42); err != nil {
		t.Fatal(err)
	}
	id := SnowflakeID()

	mid := ExtractSnowflakeMachineID(id)
	seq := ExtractSnowflakeSequence(id)
	ts := ExtractSnowflakeTime(id)

	if mid != 42 {
		t.Errorf("expected machineID 42, got %d", mid)
	}
	if seq != 0 {
		t.Errorf("expected sequence 0 on first ID, got %d", seq)
	}
	if ts.IsZero() {
		t.Error("expected non-zero time")
	}
	// ts 应在最近 5s 内
	if diff := time.Since(ts); diff < -time.Second || diff > 5*time.Second {
		t.Errorf("extracted time off by %v", diff)
	}
}

func TestSnowflakeID_SequenceIncrement(t *testing.T) {
	resetForTest()
	defer resetForTest()

	if err := InitSnowflake(1); err != nil {
		t.Fatal(err)
	}

	// Tight loop 强制同 ms: 在同一毫秒内连续取, sequence 必须严格递增.
	// 用 100ms budget, 同 ms 内至少能拿到几十个 ID.
	var ids []int64
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		ids = append(ids, SnowflakeID())
	}

	if len(ids) < 10 {
		t.Fatalf("expected to generate ≥10 IDs in 100ms, got %d", len(ids))
	}

	// 找一组同 ms 的连续 ID 断言 sequence 单调递增.
	sawSameMS := false
	for i := 1; i < len(ids); i++ {
		ts1 := ExtractSnowflakeTime(ids[i-1])
		ts2 := ExtractSnowflakeTime(ids[i])
		seq1 := ExtractSnowflakeSequence(ids[i-1])
		seq2 := ExtractSnowflakeSequence(ids[i])

		if ts1.Equal(ts2) {
			sawSameMS = true
			if seq2 <= seq1 {
				t.Fatalf("same-ms sequence not strictly increasing at i=%d: seq1=%d seq2=%d", i, seq1, seq2)
			}
		}
	}

	if !sawSameMS {
		t.Errorf("did not observe any same-ms consecutive IDs in %d samples; tight loop too slow", len(ids))
	}

	// 100ms 内 sequence 不应跨过 12-bit 边界 (4096/ms 远超 tight loop 速率).
	for _, id := range ids {
		if seq := ExtractSnowflakeSequence(id); seq > sequenceMask {
			t.Errorf("sequence %d exceeds mask %d", seq, sequenceMask)
		}
	}
}

// TestSnowflake_Next_ClockBackwardBeyondTolerance 回归测试（#72）：大幅回拨
// （超过容忍上限）不得无限持锁忙等——必须立即转进位生成：next() 马上返回，
// ID 时间戳取回拨前基准（合成时刻），OnClockBack 回调以真实回拨幅度触发
// 一次且同一轮回拨内不重复触发。
//
// 缺陷成因：回拨分支 `time.Sleep(1ms); continue` 在持有 s.mu 的情况下等时钟
// 追平——NTP 回拨 1 小时则所有 SnowflakeID() 调用阻塞 1 小时（单 mutex 全局
// 串行），进程级可用性陷阱。
func TestSnowflake_Next_ClockBackwardBeyondTolerance(t *testing.T) {
	backCh := make(chan time.Duration, 1)
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          3,
		clockBackTolerance: 5 * time.Second,
		onClockBack:        func(back time.Duration) { backCh <- back },
		lastTS:             time.Now().UnixMilli() + int64((10 * time.Minute).Milliseconds()), // 回拨 10 分钟 > 5s
	}
	base := s.lastTS

	start := time.Now()
	id := s.next()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("超容忍回拨下 next() 阻塞了 %v——必须立即转进位生成", elapsed)
	}
	// 进位生成：时间戳 = 回拨前基准，sequence 从 1 起继续。
	if ts := ExtractSnowflakeTime(id).UnixMilli(); ts != base {
		t.Fatalf("进位生成的时间戳 = %d, want 回拨前基准 %d", ts, base)
	}
	if got := ExtractSnowflakeSequence(id); got != 1 {
		t.Fatalf("sequence = %d, want 1", got)
	}
	// 回调以真实回拨幅度触发一次。
	select {
	case back := <-backCh:
		if back < 9*time.Minute {
			t.Fatalf("回调回拨幅度 = %v, want ≈10m", back)
		}
	default:
		t.Fatal("大幅回拨未触发 OnClockBack 回调")
	}
	// 同一轮回拨内继续发号：ID 递增唯一，不再重复触发回调。
	id2 := s.next()
	if id2 <= id {
		t.Fatalf("进位生成的 ID 必须递增: %d 后是 %d", id, id2)
	}
	select {
	case back := <-backCh:
		t.Fatalf("同一轮回拨不应重复触发回调, got %v", back)
	default:
	}
}

// TestSnowflake_Next_ClockBackwardWithinTolerance 回归测试（#72）：容忍上限内
// 的小幅回拨维持既有行为——持锁有界等待时钟追平后按真实时刻发号（时间戳
// 不早于回拨前基准），不会误入进位生成。
func TestSnowflake_Next_ClockBackwardWithinTolerance(t *testing.T) {
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          1,
		clockBackTolerance: 5 * time.Second,
		lastTS:             time.Now().UnixMilli() + 3, // 回拨 3ms < 5s
	}
	base := s.lastTS

	start := time.Now()
	id := s.next()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("小幅回拨的等待失控: %v（应 ≈3ms 有界）", elapsed)
	}
	if ts := ExtractSnowflakeTime(id).UnixMilli(); ts < base {
		t.Fatalf("追平后发号的时间戳 %d 早于回拨前基准 %d", ts, base)
	}
	if s.synthetic {
		t.Fatal("容忍度内的小幅回拨不应进入进位生成模式")
	}
}

// TestSnowflake_Next_SyntheticSequenceOverflow 回归测试（#72）：进位生成模式
// 下 sequence 用尽（4096/ms）时合成推进 1ms——不能回头等真实时钟（那是无限
// 等待）；整段发号 ID 唯一且单调递增。
func TestSnowflake_Next_SyntheticSequenceOverflow(t *testing.T) {
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          2,
		clockBackTolerance: 5 * time.Second,
		onClockBack:        func(time.Duration) {},          // 静音缺省 slog.Warn
		lastTS:             time.Now().UnixMilli() + 60_000, // 真实时钟落后 60s
	}
	base := s.lastTS

	const n = 4096 + 16
	seen := make(map[int64]struct{}, n)
	var prev int64
	for i := 0; i < n; i++ {
		id := s.next()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID %d at i=%d", id, i)
		}
		seen[id] = struct{}{}
		if i > 0 && id <= prev {
			t.Fatalf("ID 不再递增: %d 在 %d 之后", id, prev)
		}
		prev = id
	}
	// 4096 个号用尽后合成推进：时间戳越过回拨前基准的下一 ms。
	if ts := ExtractSnowflakeTime(prev).UnixMilli(); ts <= base {
		t.Fatalf("sequence 用尽后应合成推进到下一 ms: ts=%d base=%d", ts, base)
	}
}

// TestSnowflake_Next_SyntheticRecovers 回归测试（#72）：真实时钟追平后自动
// 退出进位生成模式，恢复按真实时刻发号（新轮回拨才会再次触发回调）。
func TestSnowflake_Next_SyntheticRecovers(t *testing.T) {
	notified := 0
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          1,
		clockBackTolerance: 0, // 任何回拨都进位生成
		onClockBack:        func(time.Duration) { notified++ },
		lastTS:             time.Now().UnixMilli() + 2, // 回拨 2ms
	}
	id := s.next()
	if !s.synthetic {
		t.Fatal("零容忍下回拨必须进入进位生成模式")
	}
	base := ExtractSnowflakeTime(id).UnixMilli()
	// 等真实时钟越过 lastTS（等待量 = 回拨量 2ms，有 deadline 兜底）。
	deadline := time.Now().Add(time.Second)
	for time.Now().UnixMilli() <= s.lastTS && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	id2 := s.next()
	if s.synthetic {
		t.Fatal("真实时钟追平后必须退出进位生成模式")
	}
	if ts := ExtractSnowflakeTime(id2).UnixMilli(); ts <= base {
		t.Fatalf("追平后的 ID 时间戳 %d 必须越过合成基准 %d", ts, base)
	}
	if notified != 1 {
		t.Fatalf("一轮进位生成只应通报一次, got %d", notified)
	}
}

// TestInitSnowflakeWith_Options 回归测试（#72）：InitSnowflakeWith 装配选项进
// 全局单例；InitSnowflake 缺省容忍上限 5s（向后兼容）。
func TestInitSnowflakeWith_Options(t *testing.T) {
	resetForTest()
	defer resetForTest()

	var gotBack time.Duration
	if err := InitSnowflakeWith(9,
		WithClockBackTolerance(time.Second),
		WithOnClockBack(func(back time.Duration) { gotBack = back }),
	); err != nil {
		t.Fatalf("InitSnowflakeWith: %v", err)
	}
	if got := SnowflakeMachineID(); got != 9 {
		t.Fatalf("machineID = %d, want 9", got)
	}
	s := defaultSnowflake.Load()
	if s.clockBackTolerance != time.Second {
		t.Fatalf("tolerance = %v, want 1s", s.clockBackTolerance)
	}
	if s.onClockBack == nil {
		t.Fatal("onClockBack 未装配")
	}
	// 回调可被调用（白盒：直接触发一轮进位生成）。
	s2 := &Snowflake{epoch: snowflakeEpoch, machineID: 9, clockBackTolerance: time.Second, onClockBack: s.onClockBack, lastTS: time.Now().UnixMilli() + 10_000}
	s2.next()
	if gotBack < 9*time.Second {
		t.Fatalf("回调收到的回拨幅度 = %v, want ≈10s", gotBack)
	}

	// 缺省路径：InitSnowflake 不带选项 → 容忍上限 5s。
	resetForTest()
	if err := InitSnowflake(4); err != nil {
		t.Fatalf("InitSnowflake: %v", err)
	}
	if got := defaultSnowflake.Load().clockBackTolerance; got != defaultClockBackTolerance {
		t.Fatalf("缺省容忍上限 = %v, want %v", got, defaultClockBackTolerance)
	}
}
