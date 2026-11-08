package uidgen

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// stubRandRead 注入必然失败的 crypto/rand 桩（#87 验收判据：注入必然失败的桩，
// 断言 E 版返回 error 且不 panic、panic 版行为不变）。经 t.Cleanup 自动恢复。
func stubRandRead(t *testing.T) {
	t.Helper()
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("getrandom: broken") }
	t.Cleanup(func() { randRead = old })
}

func TestRandomHexLengthAndCharset(t *testing.T) {
	s := RandomHex(16)
	if len(s) != 32 {
		t.Fatalf("16 字节应为 32 hex 字符，得到 %d", len(s))
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("非 hex 字符 %q", c)
		}
	}
}

// TestRandomHexNonPositivePanics 锁定 #50：nBytes<=0 panic——空串密钥是最危险
// 的缺省（「名义生成了、实际是空钥匙」），与 RandomString 空 alphabet 的防呆
// 哲学对齐；矩阵内无调用方依赖旧「静默空串」行为（全仓 grep 核过）。
func TestRandomHexNonPositivePanics(t *testing.T) {
	for _, n := range []int{0, -1, -32} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomHex(%d) 应 panic（空串密钥危险缺省）", n)
				}
			}()
			RandomHex(n)
		}()
	}
}

func TestRandomHexUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := RandomHex(16)
		if seen[s] {
			t.Fatalf("1000 次内出现重复 ID")
		}
		seen[s] = true
	}
}

func TestRandomStringUniformCharset(t *testing.T) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	s := RandomString(alphabet, 100)
	if len(s) != 100 {
		t.Fatalf("长度 %d != 100", len(s))
	}
	for _, c := range s {
		if indexAny(alphabet, byte(c)) < 0 {
			t.Fatalf("字符 %q 不在 alphabet 内", c)
		}
	}
}

func TestRandomStringSingleChar(t *testing.T) {
	if got := RandomString("x", 5); got != "xxxxx" {
		t.Fatalf("单字符 alphabet 应全同，得到 %q", got)
	}
}

func TestRandomStringEmptyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("空 alphabet 应 panic")
		}
	}()
	_ = RandomString("", 5)
}

func TestRandomStringDistribution(t *testing.T) {
	// 均匀性烟雾测试：31 字符表采 31000 次，每字符期望 1000 次，±30% 容差。
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	counts := map[byte]int{}
	s := RandomString(alphabet, 31000)
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	for _, c := range []byte(alphabet) {
		if counts[c] < 700 || counts[c] > 1300 {
			t.Fatalf("字符 %q 频次 %d 偏离均匀（期望 ~1000）", string(c), counts[c])
		}
	}
}

func indexAny(alphabet string, c byte) int {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == c {
			return i
		}
	}
	return -1
}

// TestRandomStringNonPositivePanics 锁定 #88：n<=0 panic——与 #50 对 RandomHex 的
// 修法同口径。空串密钥是最危险的缺省：空串做 HMAC key 任何人可伪造签名、空串做
// Bearer token 落库后与「无 token」不可区分（PB_TOKEN_LEN 之类漏配 ⇒ 0 时静默
// 返回 "" 会把空钥匙直接塞进 Header/DB/HMAC key）。
func TestRandomStringNonPositivePanics(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomString(alphabet, %d) 应 panic（空串密钥危险缺省，#88）", n)
				}
			}()
			RandomString("abc", n)
		}()
	}
}

// TestRandomString_MultibyteAlphabetValidUTF8 锁定 #89：按 rune 采样——多字节
// alphabet 的输出必为合法 UTF-8 且恰含 n 个字符。旧字节口径下 RandomString("中文", 1)
// 恒返回一个孤立的带头/续字节（"中文" 六个组成字节无一 ASCII），utf8.ValidString
// 恒为 false，进入 JSON/DB utf8 列/日志即损坏。
func TestRandomString_MultibyteAlphabetValidUTF8(t *testing.T) {
	const alphabet = "中文"
	for _, n := range []int{1, 3, 50} {
		s := RandomString(alphabet, n)
		if !utf8.ValidString(s) {
			t.Fatalf("n=%d 输出非法 UTF-8: %q", n, s)
		}
		if got := utf8.RuneCountInString(s); got != n {
			t.Fatalf("n=%d 输出 %d 个字符（字节长 %d）——文档声明「采样 n 个字符」须真按字符", n, got, len(s))
		}
		for _, r := range s {
			if r != '中' && r != '文' {
				t.Fatalf("字符 %q 不在 alphabet 内", r)
			}
		}
	}
}

// TestRandomString_MixedMultibyteAlphabet ASCII + 多字节混合 alphabet：输出仍是
// 合法 UTF-8 且每个 rune 都来自 alphabet（#89；旧字节口径下概率性产出断裂字节）。
func TestRandomString_MixedMultibyteAlphabet(t *testing.T) {
	const alphabet = "abc中文"
	s := RandomString(alphabet, 200)
	if !utf8.ValidString(s) {
		t.Fatalf("输出非法 UTF-8: %q", s)
	}
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("字符 %q 不在 alphabet 内", r)
		}
	}
}

// TestRandomString_AlphabetTooLarge_Panic 钉住 #52：alphabet 字符数 >256 时拒绝采样
// maxMultiple 归 0 ⇒ 死循环烧 crypto/rand——构造期 panic 当场暴露（对齐 #50 哲学）。
// #89 起判据按 rune 数计：字节口径下 300 字节的 100 个「字」被误杀，rune 口径下合法。
func TestRandomString_AlphabetTooLarge_Panic(t *testing.T) {
	// 100 个「字」= 300 字节但仅 100 rune：#89 起合法，单 rune 快路径全同输出。
	if s := RandomString(strings.Repeat("字", 100), 8); s != strings.Repeat("字", 8) {
		t.Fatalf("单字符 alphabet 应全同，得到 %q", s)
	}
	// 真 >256 rune：panic。
	var tooLarge []rune
	for i := 0; i < 300; i++ {
		tooLarge = append(tooLarge, rune(0x80+i)) // 0x80..0x1AB，非代理区，合法 UTF-8
	}
	defer func() {
		if recover() == nil {
			t.Fatal("alphabet >256 runes must panic")
		}
	}()
	RandomString(string(tooLarge), 8)
}

// TestRandomString_LargeAsciiAlphabet_Works 大 alphabet（≤256 rune）正常出串。
func TestRandomString_LargeAsciiAlphabet_Works(t *testing.T) {
	alphabet := strings.Repeat("abcdef0123456789", 16) // 256 字节 = 256 rune，恰好在上限内
	out := RandomString(alphabet, 32)
	if len(out) != 32 {
		t.Fatalf("len=%d want 32", len(out))
	}
	for _, c := range []byte(out) {
		if !strings.ContainsRune(alphabet, rune(c)) {
			t.Fatalf("char %q not in alphabet", c)
		}
	}
}

// TestRandomString_LargeMultibyteAlphabet_Works 200 rune 的多字节 alphabet（600
// 字节）在 rune 口径下合法出串——旧字节口径下这是「panic 或非法 UTF-8」二选一（#89）。
func TestRandomString_LargeMultibyteAlphabet_Works(t *testing.T) {
	var runes []rune
	for i := 0; i < 200; i++ {
		runes = append(runes, rune(0x4E00+i)) // CJK 区，无代理区
	}
	alphabet := string(runes)
	s := RandomString(alphabet, 100)
	if !utf8.ValidString(s) {
		t.Fatalf("输出非法 UTF-8: %q", s)
	}
	if utf8.RuneCountInString(s) != 100 {
		t.Fatalf("输出 %d 个字符, want 100", utf8.RuneCountInString(s))
	}
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("字符 %q 不在 alphabet 内", r)
		}
	}
}

// TestRandomHexE_Success E 版正常路径与 RandomHex 同输出形态（#87）。
func TestRandomHexE_Success(t *testing.T) {
	s, err := RandomHexE(16)
	if err != nil {
		t.Fatalf("RandomHexE() error = %v", err)
	}
	if len(s) != 32 {
		t.Fatalf("16 字节应为 32 hex 字符，得到 %d", len(s))
	}
}

// TestRandomHexE_RandFailureReturnsError 锁定 #87：crypto/rand 读取失败返回
// error 且不 panic——请求路径可就地降级，不必吞错也不必进程崩溃。
func TestRandomHexE_RandFailureReturnsError(t *testing.T) {
	stubRandRead(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RandomHexE rand 失败必须返回 error 而非 panic（#87），got %v", r)
		}
	}()
	s, err := RandomHexE(16)
	if err == nil {
		t.Fatalf("RandomHexE 必须返回 error, got %q", s)
	}
	if !strings.Contains(err.Error(), "crypto/rand 不可用") {
		t.Fatalf("错误文案应说明 crypto/rand 不可用, got %v", err)
	}
}

// TestRandomHexE_NonPositivePanics 入参非法仍 panic——E 变体只改运行期故障的
// 出口，不改入参防呆（#87 验收判据）。
func TestRandomHexE_NonPositivePanics(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomHexE(%d) 应 panic（入参防呆不变，#87）", n)
				}
			}()
			_, _ = RandomHexE(n)
		}()
	}
}

// TestRandomHex_RandFailureStillPanics panic 版行为不变（#87 验收判据：防止无意
// 改语义）。
func TestRandomHex_RandFailureStillPanics(t *testing.T) {
	stubRandRead(t)
	defer func() {
		if recover() == nil {
			t.Fatal("RandomHex rand 失败应保持 panic 语义")
		}
	}()
	RandomHex(16)
}

// TestRandomStringE_Success E 版正常路径：与 RandomString 同实现同输出形态
// （多字节 alphabet 产合法 UTF-8，#87 与 #88/#89 同族一致）。
func TestRandomStringE_Success(t *testing.T) {
	s, err := RandomStringE("abc中文", 20)
	if err != nil {
		t.Fatalf("RandomStringE() error = %v", err)
	}
	if !utf8.ValidString(s) {
		t.Fatalf("输出非法 UTF-8: %q", s)
	}
	if utf8.RuneCountInString(s) != 20 {
		t.Fatalf("输出 %d 个字符, want 20", utf8.RuneCountInString(s))
	}
}

// TestRandomStringE_RandFailureReturnsError 锁定 #87：rand 失败返回 error 不 panic。
func TestRandomStringE_RandFailureReturnsError(t *testing.T) {
	stubRandRead(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RandomStringE rand 失败必须返回 error 而非 panic（#87），got %v", r)
		}
	}()
	s, err := RandomStringE("abc", 10)
	if err == nil {
		t.Fatalf("RandomStringE 必须返回 error, got %q", s)
	}
	if !strings.Contains(err.Error(), "crypto/rand 不可用") {
		t.Fatalf("错误文案应说明 crypto/rand 不可用, got %v", err)
	}
}

// TestRandomStringE_InputValidationStillPanics 三类非法入参（n<=0 / 空 alphabet /
// 字符数 >256）在 E 版同样 panic（#87：入参防呆不变）。
func TestRandomStringE_InputValidationStillPanics(t *testing.T) {
	var tooLarge []rune
	for i := 0; i < 300; i++ {
		tooLarge = append(tooLarge, rune(0x80+i))
	}
	for name, fn := range map[string]func() error{
		"n<=0":         func() error { _, err := RandomStringE("abc", 0); return err },
		"空 alphabet":   func() error { _, err := RandomStringE("", 5); return err },
		"alphabet>256": func() error { _, err := RandomStringE(string(tooLarge), 5); return err },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomStringE [%s] 应 panic（入参防呆不变，#87）", name)
				}
			}()
			_ = fn()
		}()
	}
}

// TestRandomString_RandFailureStillPanics panic 版行为不变（#87 验收判据）。
func TestRandomString_RandFailureStillPanics(t *testing.T) {
	stubRandRead(t)
	defer func() {
		if recover() == nil {
			t.Fatal("RandomString rand 失败应保持 panic 语义")
		}
	}()
	RandomString("abc", 10)
}

// ---------------------------------------------------------------------------
// #87 后续：显式随机源变体 RandomHexFrom/RandomStringFrom(io.Reader)——
// 专供测试注入确定性/必然失败的随机源（与 E 版共用同一份取样核心 sampleRunes）
// ---------------------------------------------------------------------------

// errBoom 必然失败的随机源自报错误（单例，便于 errors.Is 断言）。
var errBoom = errors.New("boom")

// eofReader 每次读都返回 io.EOF（必然失败的随机源）。
type eofReader struct{}

func (eofReader) Read(p []byte) (int, error) { return 0, io.EOF }

// boomReader 每次读都返回业务错误（必然失败的随机源）。
type boomReader struct{}

func (boomReader) Read(p []byte) (int, error) { return 0, errBoom }

// shortReader 短读形态 reader：每次最多吐 max 字节，底层读尽后返回 io.EOF。
type shortReader struct {
	r   io.Reader
	max int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if len(p) > s.max {
		p = p[:s.max]
	}
	return s.r.Read(p)
}

// detBytes 用 math/rand 造一段确定性字节流（不触碰顶层 rand.Read）。
func detBytes(seed int64, n int) []byte {
	rr := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rr.Uint64())
	}
	return b
}

// TestRandomHexFrom_FailingReaderReturnsError #87 注入形态主判据：显式随机源
// 读取失败返回 error 且**不 panic**（EOF 与业务错误两形态，errors.Is 可判定，
// 失败不返回半截产物）。
func TestRandomHexFrom_FailingReaderReturnsError(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    io.Reader
		want error
	}{
		{"EOF", eofReader{}, io.EOF},
		{"boom", boomReader{}, errBoom},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RandomHexFrom(%s) 不应 panic，得到 %v", tc.name, r)
				}
			}()
			s, err := RandomHexFrom(tc.r, 8)
			if err == nil {
				t.Fatalf("RandomHexFrom(%s) 应返回 error，得到 (%q, nil)", tc.name, s)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("RandomHexFrom(%s) err = %v，want %v", tc.name, err, tc.want)
			}
			if s != "" {
				t.Fatalf("失败时不应返回半截产物，得到 %q", s)
			}
		}()
	}
}

// TestRandomStringFrom_FailingReaderReturnsError 同款主判据（RandomStringFrom）。
func TestRandomStringFrom_FailingReaderReturnsError(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    io.Reader
		want error
	}{
		{"EOF", eofReader{}, io.EOF},
		{"boom", boomReader{}, errBoom},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RandomStringFrom(%s) 不应 panic，得到 %v", tc.name, r)
				}
			}()
			s, err := RandomStringFrom(tc.r, "abc", 8)
			if err == nil {
				t.Fatalf("RandomStringFrom(%s) 应返回 error，得到 (%q, nil)", tc.name, s)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("RandomStringFrom(%s) err = %v，want %v", tc.name, err, tc.want)
			}
			if s != "" {
				t.Fatalf("失败时不应返回半截产物，得到 %q", s)
			}
		}()
	}
}

// TestRandomHexFrom_NilReaderPanics：nil reader 是非法入参，构造期当场暴露
// （对齐 #50 哲学——From 版的显式源是调用方的承诺，nil 不是「用默认」）。
func TestRandomHexFrom_NilReaderPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RandomHexFrom(nil, 8) 应 panic")
		}
	}()
	_, _ = RandomHexFrom(nil, 8)
}

// TestRandomHexFrom_NonPositivePanics 负对照：From 版入参校验与 panic 版完全
// 一致（checkHexArgs 单一来源）——非正长度仍是调用方 bug（#50）。
func TestRandomHexFrom_NonPositivePanics(t *testing.T) {
	for _, n := range []int{0, -1, -32} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomHexFrom(reader, %d) 应 panic（非法长度=调用方 bug）", n)
				}
			}()
			_, _ = RandomHexFrom(bytes.NewReader([]byte{1}), n)
		}()
	}
}

// TestRandomStringFrom_InputValidationPanics 负对照：From 版入参校验与 panic 版
// 完全一致（checkStringArgs 单一来源，#87/#88/#89 同族口径）——nil reader /
// n<=0 / 空 alphabet / 字符数 >256 全部 panic。
func TestRandomStringFrom_InputValidationPanics(t *testing.T) {
	var tooLarge []rune
	for i := 0; i < 300; i++ {
		tooLarge = append(tooLarge, rune(0x80+i))
	}
	for name, fn := range map[string]func(){
		"nil reader":   func() { _, _ = RandomStringFrom(nil, "abc", 8) },
		"n<=0":         func() { _, _ = RandomStringFrom(nil, "abc", 0) },
		"空 alphabet":   func() { _, _ = RandomStringFrom(bytes.NewReader([]byte{1}), "", 5) },
		"alphabet>256": func() { _, _ = RandomStringFrom(bytes.NewReader([]byte{1}), string(tooLarge), 5) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandomStringFrom [%s] 应 panic（入参防呆不变）", name)
				}
			}()
			fn()
		}()
	}
}

// TestRandomHexFrom_DeterministicBytes 注入固定字节验证 hex 编码逐字节正确。
func TestRandomHexFrom_DeterministicBytes(t *testing.T) {
	s, err := RandomHexFrom(bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67}), 8)
	if err != nil {
		t.Fatalf("不应返回 error: %v", err)
	}
	if s != "deadbeef01234567" {
		t.Fatalf("得到 %q，want %q", s, "deadbeef01234567")
	}
}

// TestRandomHexFrom_ShortReadReader 短读 reader（每次只吐 3 字节后 EOF）也必须
// 读满——io.ReadFull 循环语义（#87）。
func TestRandomHexFrom_ShortReadReader(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67}
	s, err := RandomHexFrom(&shortReader{r: bytes.NewReader(raw), max: 3}, 8)
	if err != nil {
		t.Fatalf("短读 reader 应被读满而非报错: %v", err)
	}
	if s != "deadbeef01234567" {
		t.Fatalf("得到 %q，want %q", s, "deadbeef01234567")
	}
}

// TestRandomStringFrom_DeterministicRejectionSampling 注入确定性随机源
// （math/rand seed 1）验证拒绝采样无越界：31 字符表 256%31=8 ⇒ maxMultiple=248，
// 拒绝路径被真实踩到；混合 alphabet（#89 rune 口径）产合法 UTF-8 且恰 n 个字符；
// 同种子输出可复现。
func TestRandomStringFrom_DeterministicRejectionSampling(t *testing.T) {
	const ascii = "abcdefghjkmnpqrstuvwxyz23456789"
	s, err := RandomStringFrom(rand.New(rand.NewSource(1)), ascii, 500)
	if err != nil {
		t.Fatalf("确定性随机源不应返回 error: %v", err)
	}
	if len(s) != 500 {
		t.Fatalf("长度 %d != 500", len(s))
	}
	for _, c := range []byte(s) {
		if indexAny(ascii, c) < 0 {
			t.Fatalf("字符 %q 不在 alphabet 内（拒绝采样越界）", string(c))
		}
	}
	const mixed = "abc中文"
	m, err := RandomStringFrom(rand.New(rand.NewSource(1)), mixed, 100)
	if err != nil {
		t.Fatalf("确定性随机源不应返回 error: %v", err)
	}
	if !utf8.ValidString(m) {
		t.Fatalf("多字节 alphabet 输出非法 UTF-8: %q", m)
	}
	if utf8.RuneCountInString(m) != 100 {
		t.Fatalf("输出 %d 个字符，want 100", utf8.RuneCountInString(m))
	}
	for _, r := range m {
		if !strings.ContainsRune(mixed, r) {
			t.Fatalf("字符 %q 不在 alphabet 内（拒绝采样越界）", r)
		}
	}
	again, err := RandomStringFrom(rand.New(rand.NewSource(1)), ascii, 500)
	if err != nil {
		t.Fatalf("确定性随机源不应返回 error: %v", err)
	}
	if s != again {
		t.Fatal("同种子两次生成应产出相同序列（确定性注入）")
	}
}

// TestRandomStringFrom_ShortReadReader 短读形态下取样循环也能读满（多轮读取拉块
// + 拒绝采样跨块继续），输出仍合法且恰 n 个字符。
func TestRandomStringFrom_ShortReadReader(t *testing.T) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	s, err := RandomStringFrom(&shortReader{r: bytes.NewReader(detBytes(7, 4096)), max: 3}, alphabet, 200)
	if err != nil {
		t.Fatalf("短读 reader 应被读满而非报错: %v", err)
	}
	if utf8.RuneCountInString(s) != 200 {
		t.Fatalf("输出 %d 个字符，want 200", utf8.RuneCountInString(s))
	}
	for _, c := range []byte(s) {
		if indexAny(alphabet, c) < 0 {
			t.Fatalf("字符 %q 不在 alphabet 内（拒绝采样越界）", string(c))
		}
	}
}
