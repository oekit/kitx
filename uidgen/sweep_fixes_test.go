// 清零战役回归护栏（#141/#145，2026-11-12 sweep）：ULID 的 E 变体导出面闭环
// 与日志面回归 logx 门面。
package uidgen

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/oekit/logx"
)

// #141：ULIDE 与 ULID 完全同语义（含进程内单调序列），产出可被 ParseULID 解回。
func TestULIDESemantics(t *testing.T) {
	s, err := ULIDE()
	if err != nil {
		t.Fatalf("ULIDE() error = %v, want nil", err)
	}
	if len(s) != ulidEncodedSize {
		t.Fatalf("ULIDE() len = %d, want %d", len(s), ulidEncodedSize)
	}
	gotT, ent, err := ParseULID(s)
	if err != nil {
		t.Fatalf("ParseULID(ULIDE()) error = %v", err)
	}
	if len(ent) != ulidEntropySize {
		t.Fatalf("entropy len = %d, want %d", len(ent), ulidEntropySize)
	}
	if now := time.Now(); now.Sub(gotT) > time.Minute || gotT.After(now.Add(time.Minute)) {
		t.Fatalf("ULIDE 时间戳漂移过大：got %v", gotT)
	}
	// 与 ULID() 共用同一单调状态：连续调用严格递增（字符串序 == 数值序）。
	prev := s
	for i := 0; i < 100; i++ {
		next, err := ULIDE()
		if err != nil {
			t.Fatalf("ULIDE() iter %d error = %v", i, err)
		}
		if next <= prev {
			t.Fatalf("ULIDE 必须维持严格单调（#141 与 ULID 同语义）：%v -> %v", prev, next)
		}
		prev = next
	}
}

// #141：ULIDFromTimeE 与 ULIDFromTime 同语义——回填时间可解回，且不参与单调序列。
func TestULIDFromTimeESemantics(t *testing.T) {
	ts := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	s, err := ULIDFromTimeE(ts)
	if err != nil {
		t.Fatalf("ULIDFromTimeE() error = %v, want nil", err)
	}
	if len(s) != ulidEncodedSize {
		t.Fatalf("ULIDFromTimeE() len = %d, want %d", len(s), ulidEncodedSize)
	}
	gotT, _, err := ParseULID(s)
	if err != nil {
		t.Fatalf("ParseULID() error = %v", err)
	}
	if !gotT.Equal(ts.Truncate(time.Millisecond)) {
		t.Fatalf("回填时间 = %v, want %v", gotT, ts.Truncate(time.Millisecond))
	}
}

// #141：crypto/rand 读取失败（运行期环境故障）——E 版返回 error 出口、panic 版
// 委托 E 版保持同文案 panic（与 RandomHex/RandomHexE 的 #87 分层完全一致）。
func TestULIDECryptoRandFailure(t *testing.T) {
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("getrandom: broken") }
	t.Cleanup(func() { randRead = old })

	if _, err := ULIDE(); err == nil {
		t.Fatal("crypto/rand 故障时 ULIDE 必须返回 error（#141/#87 请求路径 error 出口）")
	} else if !strings.Contains(err.Error(), "crypto/rand 不可用") {
		t.Fatalf("错误文案应与 randomBytes 单一来源一致，got %v", err)
	}
	if _, err := ULIDFromTimeE(time.Now()); err == nil {
		t.Fatal("crypto/rand 故障时 ULIDFromTimeE 必须返回 error（#141/#87）")
	}

	// panic 版委托 E 版：同款文案。
	assertPanicContains(t, "ULID", "crypto/rand 不可用", func() { ULID() })
	assertPanicContains(t, "ULIDFromTime", "crypto/rand 不可用", func() { ULIDFromTime(time.Now()) })
}

// #141：ULIDFromTimeE 的入参越界仍按 panic 口径（调用方 bug，与 checkHexArgs
// 防呆分层一致）——只有 crypto/rand 故障走 error。
func TestULIDFromTimeEOutOfRangePanics(t *testing.T) {
	assertPanicContains(t, "ULIDFromTimeE", "超出 48 bit", func() { ULIDFromTimeE(time.UnixMilli(-1)) })
}

// assertPanicContains 断言 fn panic 且消息包含 want（panic 版委托测试共用）。
func assertPanicContains(t *testing.T, name, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("[%s] 必须 panic，got nil", name)
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, want) {
			t.Fatalf("[%s] panic 消息应包含 %q，got %v", name, want, r)
		}
	}()
	fn()
}

// #145：uidgen 的日志必须走 logx 门面——SetDefault 换后端后告警跟着走
// （此前直连标准库 slog 默认 handler，绕过后端替换与 LOG_LEVEL），错误字段名
// 用 logx.ErrKey（此前手写 "err" 字面量，违反 AGENTS.md 红线）。
func TestSnowflakeLogsFlowThroughLogxBackend(t *testing.T) {
	var buf bytes.Buffer
	prev := logx.Default()
	t.Cleanup(func() { logx.SetDefault(prev) })
	backend := logx.NewSlogLogger("myapp",
		logx.WithHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	logx.SetDefault(backend)

	t.Run("MACHINE_ID 未设置经后端告警", func(t *testing.T) {
		resetForTest()
		t.Cleanup(resetForTest)
		buf.Reset()
		t.Setenv("MACHINE_ID", "")
		if err := InitSnowflakeFromEnv(); err != nil {
			t.Fatalf("InitSnowflakeFromEnv() error = %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "MACHINE_ID not set") {
			t.Fatalf("告警必须落 logx 后端（#145：不再直连 slog），got %q", out)
		}
		if !strings.Contains(out, "kitx/uidgen") {
			t.Fatalf("告警必须带组件名 kitx/uidgen（Delegating 懒解析），got %q", out)
		}
	})

	t.Run("非法 MACHINE_ID 带 ErrKey 错误字段", func(t *testing.T) {
		resetForTest()
		t.Cleanup(resetForTest)
		buf.Reset()
		t.Setenv("MACHINE_ID", "not-a-number")
		if err := InitSnowflakeFromEnv(); err != nil {
			t.Fatalf("InitSnowflakeFromEnv() error = %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "invalid MACHINE_ID") {
			t.Fatalf("告警必须落 logx 后端，got %q", out)
		}
		if !strings.Contains(out, logx.ErrKey+"=") {
			t.Fatalf("错误字段名必须是 logx.ErrKey（值 %q），got %q", logx.ErrKey, out)
		}
	})

	t.Run("回拨兜底告警经后端", func(t *testing.T) {
		buf.Reset()
		s := &Snowflake{clockBackTolerance: defaultClockBackTolerance}
		s.notifyClockBack(30 * time.Second)
		if out := buf.String(); !strings.Contains(out, "clock moved back") {
			t.Fatalf("回拨告警必须落 logx 后端（#145），got %q", out)
		}
	})
}
