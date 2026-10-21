package uidgen

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// refDec 是本测试自带的 Crockford Base32 反查表，与被测实现的那张表相互独立
// （oracle 不复用被检对象的解析逻辑，否则两边共享盲区、一起绿）。
var refDec [256]byte

func init() {
	for i := range refDec {
		refDec[i] = 0xFF
	}
	const alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < len(alpha); i++ {
		refDec[alpha[i]] = byte(i)
		refDec[alpha[i]|0x20] = byte(i)
	}
}

// referenceDecodeULID 用 oklog/ulid 的解码公式（字节位运算直写）解 ULID。
//
// 与本包实现的「5 bit 分组」路径是两条独立算法：前者按字节拼，后者按
// 容器移位。两者交叉一致，才能说明位布局真的对——共用一套位运算的话，
// 实现错了断言也会跟着错。
func referenceDecodeULID(s string) (ts int64, entropy [ulidEntropySize]byte, err error) {
	if len(s) != ulidEncodedSize {
		return 0, entropy, errors.New("bad length")
	}
	for i := 0; i < ulidEncodedSize; i++ {
		if refDec[s[i]] == 0xFF {
			return 0, entropy, errors.New("bad char")
		}
	}
	var id [16]byte
	id[0] = (refDec[s[0]] << 5) | refDec[s[1]]
	id[1] = (refDec[s[2]] << 3) | (refDec[s[3]] >> 2)
	id[2] = (refDec[s[3]] << 6) | (refDec[s[4]] << 1) | (refDec[s[5]] >> 4)
	id[3] = (refDec[s[5]] << 4) | (refDec[s[6]] >> 1)
	id[4] = (refDec[s[6]] << 7) | (refDec[s[7]] << 2) | (refDec[s[8]] >> 3)
	id[5] = (refDec[s[8]] << 5) | refDec[s[9]]

	id[6] = (refDec[s[10]] << 3) | (refDec[s[11]] >> 2)
	id[7] = (refDec[s[11]] << 6) | (refDec[s[12]] << 1) | (refDec[s[13]] >> 4)
	id[8] = (refDec[s[13]] << 4) | (refDec[s[14]] >> 1)
	id[9] = (refDec[s[14]] << 7) | (refDec[s[15]] << 2) | (refDec[s[16]] >> 3)
	id[10] = (refDec[s[16]] << 5) | refDec[s[17]]
	id[11] = (refDec[s[18]] << 3) | (refDec[s[19]] >> 2)
	id[12] = (refDec[s[19]] << 6) | (refDec[s[20]] << 1) | (refDec[s[21]] >> 4)
	id[13] = (refDec[s[21]] << 4) | (refDec[s[22]] >> 1)
	id[14] = (refDec[s[22]] << 7) | (refDec[s[23]] << 2) | (refDec[s[24]] >> 3)
	id[15] = (refDec[s[24]] << 5) | refDec[s[25]]

	ts = int64(id[5]) | int64(id[4])<<8 | int64(id[3])<<16 |
		int64(id[2])<<24 | int64(id[1])<<32 | int64(id[0])<<40
	copy(entropy[:], id[6:])
	return ts, entropy, nil
}

// TestULIDGoldenVectors 用权威向量钉住位布局。
//
// 向量来自 ULID 规范与 oklog/ulid 的测试用例（独立实现的结果，不是从本包
// 实现反推的）：oklog 的 Alizain 兼容用例与其溢出边界用例。
func TestULIDGoldenVectors(t *testing.T) {
	cases := []struct {
		name    string
		ts      int64
		entropy [ulidEntropySize]byte
		want    string
	}{
		{
			name: "oklog Alizain 兼容向量（ts=1469918176385，熵全 0）",
			ts:   1469918176385,
			want: "01ARYZ6S410000000000000000",
		},
		{
			name: "全 0",
			want: "00000000000000000000000000",
		},
		{
			name:    "最大合法 ULID（首字符 '7'，熵全 0xFF）",
			ts:      ulidMaxTimestamp,
			entropy: [ulidEntropySize]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want:    "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
		},
		{
			name: "首字符 '7'、其余全 0",
			ts:   246290604621824, // 7 << 45
			want: "70000000000000000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := encodeULID(tc.ts, tc.entropy)
			if got != tc.want {
				t.Fatalf("编码 = %q, 期望 %q", got, tc.want)
			}
			// 解回来必须一致
			ts, err := decodeULIDTimestamp([]byte(got[:ulidTimestampChars]))
			if err != nil {
				t.Fatalf("解时间戳失败: %v", err)
			}
			if ts != tc.ts {
				t.Fatalf("解出时间戳 = %d, 期望 %d", ts, tc.ts)
			}
			var back [ulidEntropySize]byte
			if err := decodeULIDEntropy(&back, []byte(got[ulidTimestampChars:])); err != nil {
				t.Fatalf("解熵失败: %v", err)
			}
			if back != tc.entropy {
				t.Fatalf("解出熵 = %x, 期望 %x", back, tc.entropy)
			}
		})
	}
}

// TestULIDAgainstReferenceDecoder 用 oklog 的字节位运算做交叉校验。
//
// 随机取时间戳与熵，编码后交给参照实现解码，位布局不一致立刻暴露。
func TestULIDAgainstReferenceDecoder(t *testing.T) {
	rng := rand.New(rand.NewSource(20261021))
	for i := 0; i < 2000; i++ {
		ts := rng.Int63n(ulidMaxTimestamp + 1)
		var entropy [ulidEntropySize]byte
		_, _ = rng.Read(entropy[:])

		s := encodeULID(ts, entropy)
		refTS, refEntropy, err := referenceDecodeULID(s)
		if err != nil {
			t.Fatalf("参照实现解码 %q 失败: %v", s, err)
		}
		if refTS != ts {
			t.Fatalf("%q: 参照解出时间戳 %d, 期望 %d", s, refTS, ts)
		}
		if refEntropy != entropy {
			t.Fatalf("%q: 参照解出熵 %x, 期望 %x", s, refEntropy, entropy)
		}
	}
}

// TestParseULIDGoldenVectors 用权威向量钉住解析侧。
func TestParseULIDGoldenVectors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantTS   int64
		wantEnts string // 熵的 hex
	}{
		{
			name:     "oklog Alizain 兼容向量",
			input:    "01ARYZ6S410000000000000000",
			wantTS:   1469918176385,
			wantEnts: "00000000000000000000",
		},
		{
			name:     "全 0",
			input:    "00000000000000000000000000",
			wantTS:   0,
			wantEnts: "00000000000000000000",
		},
		{
			name:     "最大合法 ULID",
			input:    "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
			wantTS:   ulidMaxTimestamp,
			wantEnts: "FFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:     "首字符 '7'、其余全 0",
			input:    "70000000000000000000000000",
			wantTS:   246290604621824,
			wantEnts: "00000000000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTS, gotEnt, err := ParseULID(tc.input)
			if err != nil {
				t.Fatalf("解析 %q 失败: %v", tc.input, err)
			}
			if gotTS.UnixMilli() != tc.wantTS {
				t.Fatalf("时间戳 = %d, 期望 %d", gotTS.UnixMilli(), tc.wantTS)
			}
			if hex := strings.ToUpper(hex.EncodeToString(gotEnt)); hex != tc.wantEnts {
				t.Fatalf("熵 = %s, 期望 %s", hex, tc.wantEnts)
			}
		})
	}
}

// TestParseULIDErrors 覆盖三类非法输入。
func TestParseULIDErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"空串", ""},
		{"过短", "01ARYZ6S4100000000000000"},
		{"过长", "01ARYZ6S4100000000000000000"},
		{"含字母 I（不在 Crockford 表内）", "01ARYZ6S4I0000000000000000"},
		{"含字母 L（不在 Crockford 表内）", "01ARYZ6S4L0000000000000000"},
		{"含字母 O（不在 Crockford 表内）", "01ARYZ6S4O0000000000000000"},
		{"含字母 U（不在 Crockford 表内）", "01ARYZ6S4U0000000000000000"},
		{"含连字符", "01ARYZ6S4-0000000000000000"},
		{"含空格", "01ARYZ6S4 000000000000000"},
		{"首字符溢出（'8'）", "80000000000000000000000000"},
		{"首字符溢出（'Z'）", "ZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{"首字符溢出（'9'）", "90000000000000000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseULID(tc.input)
			if err == nil {
				t.Fatalf("解析 %q 应当失败", tc.input)
			}
			if !errors.Is(err, ErrInvalidULID) {
				t.Fatalf("错误 %v 未包装 ErrInvalidULID", err)
			}
		})
	}
}

// TestParseULIDCaseInsensitive 验证大小写不敏感（ULID 规范如此）。
func TestParseULIDCaseInsensitive(t *testing.T) {
	const s = "01ARYZ6S410000000000000000"
	upperTS, upperEnt, err := ParseULID(s)
	if err != nil {
		t.Fatalf("解析大写失败: %v", err)
	}
	lowerTS, lowerEnt, err := ParseULID(strings.ToLower(s))
	if err != nil {
		t.Fatalf("解析小写失败: %v", err)
	}
	if !upperTS.Equal(lowerTS) {
		t.Fatalf("大小写解析出不同时间戳: %v vs %v", upperTS, lowerTS)
	}
	if !bytes.Equal(upperEnt, lowerEnt) {
		t.Fatalf("大小写解析出不同熵: %x vs %x", upperEnt, lowerEnt)
	}
}

// TestULIDRoundTrip 生成后解析回时间戳与熵。
func TestULIDRoundTrip(t *testing.T) {
	before := time.Now().Add(-time.Second)
	s := ULID()
	after := time.Now().Add(time.Second)

	ts, entropy, err := ParseULID(s)
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", s, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Fatalf("时间戳 %v 不在 [%v, %v] 区间", ts, before, after)
	}
	if len(entropy) != ulidEntropySize {
		t.Fatalf("熵长度 = %d, 期望 %d", len(entropy), ulidEntropySize)
	}
	// 解析结果再编码必须得到原串
	if got := encodeULID(ts.UnixMilli(), [ulidEntropySize]byte(entropy)); got != s {
		t.Fatalf("回编 = %q, 期望 %q", got, s)
	}
}

// TestULIDCharacterSet 验证字符集、长度与首字符约束。
func TestULIDCharacterSet(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := ULID()
		if len(s) != ulidEncodedSize {
			t.Fatalf("长度 = %d, 期望 %d", len(s), ulidEncodedSize)
		}
		for _, c := range s {
			if !strings.ContainsRune(ulidEncoding, c) {
				t.Fatalf("字符 %q 不在 Crockford Base32 表内: %q", c, s)
			}
		}
		// 26 字符可承载 130 bit，ULID 只有 128 bit：首字符取值必须 ≤ '7'
		if s[0] > '7' {
			t.Fatalf("首字符 %q 超出 128 bit 范围: %q", s[0], s)
		}
	}
}

// TestULIDMonotonic 验证同毫秒内严格递增。
func TestULIDMonotonic(t *testing.T) {
	const n = 5000
	prev := ULID()
	for i := 0; i < n; i++ {
		cur := ULID()
		if cur <= prev {
			t.Fatalf("第 %d 个 ID 未严格递增: %q <= %q", i, cur, prev)
		}
		prev = cur
	}
}

// TestULIDMonotonicMatchesTime 验证字典序与时间序一致。
func TestULIDMonotonicMatchesTime(t *testing.T) {
	ids := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		ids = append(ids, ULID())
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)

	for _, s := range ids {
		ts, _, err := ParseULID(s)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", s, err)
		}
		if ts.After(time.Now().Add(time.Second)) || ts.Before(time.Now().Add(-time.Hour)) {
			t.Fatalf("%q 的时间戳 %v 明显偏离当前时间", s, ts)
		}
	}
	// 排序后时间戳必须非降
	var prev time.Time
	for i, s := range sorted {
		ts, _, err := ParseULID(s)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", s, err)
		}
		if i > 0 && ts.Before(prev) {
			t.Fatalf("排序后时间戳倒流: %v < %v", ts, prev)
		}
		prev = ts
	}
}

// TestULIDClockSkewFrozen 验证时钟回拨时冻结在上次的毫秒。
func TestULIDClockSkewFrozen(t *testing.T) {
	ulidMono.mu.Lock()
	savedMS, savedEnt := ulidMono.lastMS, ulidMono.lastEnt
	ulidMono.mu.Unlock()
	defer func() {
		ulidMono.mu.Lock()
		ulidMono.lastMS, ulidMono.lastEnt = savedMS, savedEnt
		ulidMono.mu.Unlock()
	}()

	future := time.Now().UnixMilli() + 5000
	ulidMono.mu.Lock()
	ulidMono.lastMS = future
	ulidMono.lastEnt = [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	ulidMono.mu.Unlock()

	ts, entropy, err := ParseULID(ULID())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ts.UnixMilli() != future {
		t.Fatalf("时钟回拨后时间戳 = %d, 期望冻结在 %d", ts.UnixMilli(), future)
	}
	// 熵按最低位递增（ULID 规范：least significant bit position, with carrying）
	if entropy[ulidEntropySize-1] != 0x02 {
		t.Fatalf("熵未递增: %x", entropy)
	}
}

// TestULIDEntropyOverflowCarries 验证 80 bit 熵用尽时进位到下一毫秒。
func TestULIDEntropyOverflowCarries(t *testing.T) {
	ulidMono.mu.Lock()
	savedMS, savedEnt := ulidMono.lastMS, ulidMono.lastEnt
	ulidMono.mu.Unlock()
	defer func() {
		ulidMono.mu.Lock()
		ulidMono.lastMS, ulidMono.lastEnt = savedMS, savedEnt
		ulidMono.mu.Unlock()
	}()

	now := time.Now().UnixMilli()
	ulidMono.mu.Lock()
	ulidMono.lastMS = now
	ulidMono.lastEnt = [ulidEntropySize]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ulidMono.mu.Unlock()

	ts, entropy, err := ParseULID(ULID())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ts.UnixMilli() != now+1 {
		t.Fatalf("熵溢出后时间戳 = %d, 期望进位到 %d", ts.UnixMilli(), now+1)
	}
	for i, b := range entropy {
		if b != 0 {
			t.Fatalf("进位后熵未归零: %x", entropy)
		}
		_ = i
	}
}

// TestULIDFromTime 验证按指定时间戳生成。
func TestULIDFromTime(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
	}{
		{"Unix 纪元", time.Unix(0, 0)},
		{"已知时刻", time.Unix(1469918176, 385*int64(time.Millisecond))},
		{"当下", time.Now()},
		{"最大可表示时刻", time.Unix(ulidMaxTimestamp/1000, (ulidMaxTimestamp%1000)*int64(time.Millisecond))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ULIDFromTime(tc.in)
			ts, _, err := ParseULID(s)
			if err != nil {
				t.Fatalf("解析 %q 失败: %v", s, err)
			}
			if ts.UnixMilli() != tc.in.UnixMilli() {
				t.Fatalf("时间戳 = %d, 期望 %d", ts.UnixMilli(), tc.in.UnixMilli())
			}
		})
	}
}

// TestULIDFromTimeOutOfRangePanics 验证越界时间戳 panic 而非静默截断。
func TestULIDFromTimeOutOfRangePanics(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
	}{
		{"Unix 纪元之前", time.Unix(0, 0).Add(-time.Millisecond)},
		{"超出 48 bit 上限", time.Unix((ulidMaxTimestamp+1)/1000, ((ulidMaxTimestamp+1)%1000)*int64(time.Millisecond))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("越界时间戳应当 panic")
				}
			}()
			_ = ULIDFromTime(tc.in)
		})
	}
}

// TestULIDConcurrentUnique 验证并发下不重复（-race 同时验证无数据竞争）。
func TestULIDConcurrentUnique(t *testing.T) {
	const goroutines, each = 8, 500

	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*each)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 0, each)
			for i := 0; i < each; i++ {
				local = append(local, ULID())
			}
			mu.Lock()
			defer mu.Unlock()
			for _, s := range local {
				seen[s] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*each {
		t.Fatalf("唯一 ID 数 = %d, 期望 %d", len(seen), goroutines*each)
	}
}

// TestIncULIDEntropy 表驱动覆盖进位与溢出。
func TestIncULIDEntropy(t *testing.T) {
	cases := []struct {
		name      string
		in        [ulidEntropySize]byte
		want      [ulidEntropySize]byte
		wantNoOvf bool
	}{
		{
			name:      "末字节加一",
			in:        [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:      [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantNoOvf: true,
		},
		{
			name:      "末字节进位",
			in:        [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
			want:      [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantNoOvf: true,
		},
		{
			name:      "多字节连续进位",
			in:        [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF},
			want:      [ulidEntropySize]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
			wantNoOvf: true,
		},
		{
			name:      "全 0xFF 溢出",
			in:        [ulidEntropySize]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want:      [ulidEntropySize]byte{},
			wantNoOvf: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.in
			got := incULIDEntropy(&e)
			if got != tc.wantNoOvf {
				t.Fatalf("溢出标记 = %v, 期望 %v", got, tc.wantNoOvf)
			}
			if e != tc.want {
				t.Fatalf("熵 = %x, 期望 %x", e, tc.want)
			}
		})
	}
}
