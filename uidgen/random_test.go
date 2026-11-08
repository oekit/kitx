package uidgen

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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
