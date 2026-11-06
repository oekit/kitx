package uidgen

import (
	"strings"
	"testing"
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

// TestRandomString_AlphabetTooLarge_Panic 钉住 #52：alphabet 字节数 >256 时拒绝采样
// maxMultiple 归 0 ⇒ 死循环烧 crypto/rand——构造期 panic 当场暴露（对齐 #50 哲学）。
func TestRandomString_AlphabetTooLarge_Panic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("alphabet >256 bytes must panic")
		}
	}()
	RandomString(strings.Repeat("字", 100), 8) // byte len = 300
}

// TestRandomString_LargeAsciiAlphabet_Works 大 alphabet（≤256 字节）正常出串。
// 注：128<len≤256 的多字节 alphabet 按字节采样会产出 UTF-8 断裂字节（#52 的
// 既有次生问题，本修复只拦死循环）——多字节字符集支持需按 rune 采样重构。
func TestRandomString_LargeAsciiAlphabet_Works(t *testing.T) {
	alphabet := strings.Repeat("abcdef0123456789", 16) // 256 字节，恰好在上限内
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
