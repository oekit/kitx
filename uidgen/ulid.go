package uidgen

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oekit/pkg/errors"
)

const (
	// ulidEncodedSize 是 ULID 规范字符串长度：10 字符时间戳 + 16 字符熵。
	ulidEncodedSize = 26
	// ulidTimestampChars 是 48 bit 毫秒时间戳占用的字符数。
	ulidTimestampChars = 10
	// ulidEntropyChars 是 80 bit 熵占用的字符数（16 × 5 bit，恰好无冗余）。
	ulidEntropyChars = 16
	// ulidEntropySize 是熵的字节数（80 bit）。
	ulidEntropySize = 10
	// ulidTimestampMask 是 48 bit 时间戳的掩码。
	ulidTimestampMask = uint64(1)<<48 - 1
	// ulidMaxTimestamp 是 48 bit 毫秒时间戳上限（Unix 纪元毫秒，公元 10889 年）。
	ulidMaxTimestamp = int64(ulidTimestampMask)
)

// ulidEncoding 是 Crockford Base32 字母表，剔除 I/L/O/U 避免手抄歧义。
//
// 该表严格按 ASCII 升序排列（'0'..'9' < 'A'..'Z' 且中间跳过的四个字母
// 不影响单调），因此**字符串字典序 == 编码数值序**——这是 ULID 能做
// range scan 的根本原因。Snowflake 转十进制字符串做不到这点（"10" < "9"）。
const ulidEncoding = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulidDecoding 是 ulidEncoding 的反查表，非法字符记 0xFF。
//
// 大小写映射到同一数值：ULID 规范要求大小写不敏感（oklog/ulid 与
// ulid/javascript 均如此）。数字的 c|0x20 仍是自身，字母则落到小写区。
var ulidDecoding = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = 0xFF
	}
	for i := 0; i < len(ulidEncoding); i++ {
		c := ulidEncoding[i]
		t[c] = byte(i)
		t[c|0x20] = byte(i)
	}
	return t
}()

// ErrInvalidULID 表示字符串不是合法 ULID：长度不对、含非法字符，
// 或超出 128 bit 范围（首字符取值大于 '7'）。
//
// 调用方用 errors.Is(err, uidgen.ErrInvalidULID) 判定；具体原因在错误消息里。
var ErrInvalidULID = errors.New("uidgen: invalid ULID")

// ulidMono 是 ULID() 的进程内单调状态。
//
// 只保护「同毫秒递增」这一个状态量，临界区是几次算术；熵的随机读取放在
// 锁外，避免 crypto/rand 的系统调用把 ID 生成串行化。
var ulidMono struct {
	mu      sync.Mutex
	lastMS  int64
	lastEnt [ulidEntropySize]byte
}

// ULID 返回 26 字符的 ULID（Universally Unique Lexicographically Sortable Identifier）。
//
// 结构 = 48 bit 毫秒时间戳（Unix 纪元）+ 80 bit 熵，Crockford Base32 编码。
// 适用于「文本主键 + 按 ID 做时间序 range scan」这一类需求：
// Snowflake 是 int64（不能直接当文本主键），UUID 是随机串（字典序与时间无关）。
//
// 同一毫秒内进程内**严格单调**：熵逐个递增，80 bit 熵用尽则进位到下一毫秒。
// 时钟回拨时冻结在上一次的毫秒继续递增熵，保证不会出现更小的 ID。
//
// 零第三方依赖：crypto/rand + 标准库。
func ULID() string {
	// 熵在锁外读：临界区只留几次算术。
	var entropy [ulidEntropySize]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("uidgen: crypto/rand 不可用: " + err.Error())
	}
	now := time.Now().UnixMilli()

	ulidMono.mu.Lock()
	defer ulidMono.mu.Unlock()

	ms, ent := now, entropy
	if now <= ulidMono.lastMS {
		// 同毫秒（或时钟回拨）：熵 +1，维持严格单调。
		ms = ulidMono.lastMS
		ent = ulidMono.lastEnt
		if !incULIDEntropy(&ent) {
			// 80 bit 熵用尽：进位到下一毫秒，熵归零。
			ms++
			ent = [ulidEntropySize]byte{}
		}
	}
	ulidMono.lastMS, ulidMono.lastEnt = ms, ent
	return encodeULID(ms, ent)
}

// ULIDFromTime 用指定时间戳生成 ULID，便于按业务时间回填 ID。
//
// 时间戳取 t 的 Unix 毫秒；熵为随机值。**不参与 ULID() 的进程内单调序列**
// ——回填的业务时间可能早于当前时间，混进单调序列会破坏它的单调性。
// 同一 t 多次调用得到的 ULID 彼此无序，需要有序时请用 ULID()。
//
// t 超出 48 bit 毫秒时间戳范围（Unix 纪元之前，或公元 10889 年之后）时 panic：
// 这种时间戳编不出合法 ULID，静默截断会得到一个「时间不对但看着正常」的 ID。
func ULIDFromTime(t time.Time) string {
	ms := t.UnixMilli()
	if ms < 0 || ms > ulidMaxTimestamp {
		panic("uidgen: ULIDFromTime 时间戳超出 48 bit 毫秒范围")
	}
	var entropy [ulidEntropySize]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("uidgen: crypto/rand 不可用: " + err.Error())
	}
	return encodeULID(ms, entropy)
}

// ParseULID 解析 ULID，返回它的毫秒时间戳与 80 bit 熵（10 字节）。
//
// 大小写不敏感（ULID 规范如此）。长度不对、含非法字符、或超出 128 bit
// （首字符取值大于 '7'）时返回包装了 ErrInvalidULID 的错误。
func ParseULID(s string) (time.Time, []byte, error) {
	if len(s) != ulidEncodedSize {
		return time.Time{}, nil, errors.Wrap(ErrInvalidULID, "uidgen: ParseULID 长度非法",
			"len", len(s), "want", ulidEncodedSize)
	}
	// 26 字符可承载 130 bit，ULID 只有 128 bit：多出的 2 bit 落在**首字符**的
	// 低 2 位，首字符取值必须 ≤ '7'，否则多出的 2 bit 会静默错位到时间戳上。
	if v := ulidDecoding[s[0]]; v == 0xFF {
		return time.Time{}, nil, errors.Wrap(ErrInvalidULID, "uidgen: ParseULID 非法字符",
			"at", 0, "char", string(s[0]))
	} else if v > 7 {
		return time.Time{}, nil, errors.Wrap(ErrInvalidULID, "uidgen: ParseULID 超出 128 bit 范围",
			"char", string(s[0]))
	}
	ts, err := decodeULIDTimestamp([]byte(s[:ulidTimestampChars]))
	if err != nil {
		return time.Time{}, nil, err
	}
	var entropy [ulidEntropySize]byte
	if err := decodeULIDEntropy(&entropy, []byte(s[ulidTimestampChars:ulidTimestampChars+ulidEntropyChars])); err != nil {
		return time.Time{}, nil, err
	}
	return time.UnixMilli(ts), entropy[:], nil
}

// encodeULID 把 48 bit 毫秒时间戳 + 80 bit 熵编成 26 字符 ULID。
func encodeULID(ts int64, entropy [ulidEntropySize]byte) string {
	var out [ulidEncodedSize]byte
	encodeULIDTimestamp(out[:ulidTimestampChars], ts)
	encodeULIDEntropy(out[ulidTimestampChars:ulidTimestampChars+ulidEntropyChars], &entropy)
	return string(out[:])
}

// encodeULIDTimestamp 把 48 bit 时间戳编成 10 个 Crockford Base32 字符。
//
// 布局：时间戳右对齐进 50 bit 容器（高位 2 bit 恒为 0），再按 5 bit 一组
// 从高位切出 10 个字符。冗余的 2 bit 落在**首字符**的低 2 位（首字符取值
// 只能是 '0'..'7'）——不是末位；解码侧必须用同一口径，否则解出的时间戳
// 会静默错位。
func encodeULIDTimestamp(dst []byte, ts int64) {
	v := uint64(ts) & ulidTimestampMask
	for i := 0; i < ulidTimestampChars; i++ {
		dst[i] = ulidEncoding[(v>>uint(ulidTimestampChars*5-5-5*i))&0x1F]
	}
}

// encodeULIDEntropy 把 80 bit 熵编成 16 个 Crockford Base32 字符。
//
// 80 bit 恰好 16 × 5，无冗余位：按字节流从高位到低位切 5 bit 一组。
func encodeULIDEntropy(dst []byte, entropy *[ulidEntropySize]byte) {
	var acc uint32
	var nbits uint
	idx := 0
	for _, b := range entropy[:] {
		acc = acc<<8 | uint32(b)
		nbits += 8
		for nbits >= 5 {
			nbits -= 5
			dst[idx] = ulidEncoding[(acc>>nbits)&0x1F]
			idx++
			acc &= (1 << nbits) - 1
		}
	}
}

// decodeULIDTimestamp 解出 48 bit 毫秒时间戳。
//
// 10 个 5 bit 字符拼回 50 bit 容器后取低 48 位；首字符 ≤ '7' 的前置校验
// 保证高 2 bit 为 0（调用方 ParseULID 负责校验）。
func decodeULIDTimestamp(src []byte) (int64, error) {
	var c uint64
	for _, ch := range src {
		v := ulidDecoding[ch]
		if v == 0xFF {
			return 0, errors.Wrap(ErrInvalidULID, "uidgen: ParseULID 非法字符", "char", string(ch))
		}
		c = c<<5 | uint64(v)
	}
	return int64(c & ulidTimestampMask), nil
}

// decodeULIDEntropy 解出 80 bit 熵。
func decodeULIDEntropy(dst *[ulidEntropySize]byte, src []byte) error {
	var acc uint32
	var nbits uint
	idx := 0
	for _, ch := range src {
		v := ulidDecoding[ch]
		if v == 0xFF {
			return errors.Wrap(ErrInvalidULID, "uidgen: ParseULID 非法字符", "char", string(ch))
		}
		acc = acc<<5 | uint32(v)
		nbits += 5
		for nbits >= 8 {
			nbits -= 8
			dst[idx] = byte(acc >> nbits)
			idx++
			acc &= (1 << nbits) - 1
		}
	}
	return nil
}

// incULIDEntropy 把 80 bit 熵（big-endian）加一。
//
// 溢出（熵全为 0xFF）时返回 false，此时熵已被回绕成全 0——调用方据此
// 进位到下一毫秒，保证 ID 仍然严格递增。
func incULIDEntropy(e *[ulidEntropySize]byte) bool {
	for i := ulidEntropySize - 1; i >= 0; i-- {
		e[i]++
		if e[i] != 0 {
			return true
		}
	}
	return false
}
