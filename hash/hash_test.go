package hash

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// TestMd5Hex_Vector RFC 1327 标准向量 + 输出格式（32 位小写 hex）。
func TestMd5Hex_Vector(t *testing.T) {
	cases := map[string]string{
		"":               "d41d8cd98f00b204e9800998ecf8427e",
		"a":              "0cc175b9c0f1b6a831c399e269772661",
		"abc":            "900150983cd24fb0d6963f7d28e17f72",
		"message digest": "f96b697d7cb7938d525a2f31aaf161d0",
	}
	for in, want := range cases {
		got := Md5Hex(in)
		if got != want {
			t.Fatalf("Md5Hex(%q) = %q, want %q", in, got, want)
		}
		if len(got) != 32 {
			t.Fatalf("Md5Hex(%q) len = %d, want 32", in, len(got))
		}
	}
}

// TestMd5Bytes 与标准库逐字节一致 + Md5Hex 为其 hex 编码（同族互证）。
func TestMd5Bytes(t *testing.T) {
	got := Md5Bytes([]byte("abc"))
	want := md5.Sum([]byte("abc"))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("Md5Bytes = %v, want %v", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("Md5Bytes len = %d, want 16", len(got))
	}
	if hex.EncodeToString(got) != Md5Hex("abc") {
		t.Fatal("Md5Hex must be the hex encoding of Md5Bytes")
	}
}

// TestMd5Hex_FormatStability 格式稳定承诺的固化：与 ekit 时代既有的
// 手写实现输出逐字节一致（存量缓存键/短 code 依赖此性质，pkg#10）。
func TestMd5Hex_FormatStability(t *testing.T) {
	// 业务仓手写副本的算法：md5.New() + hex.EncodeToString(Sum(nil))
	legacy := func(s string) string {
		h := md5.New()
		h.Write([]byte(s))
		return hex.EncodeToString(h.Sum(nil))
	}
	for _, s := range []string{"", "k:v1|v2|v3", "1760000000", "中文参数序列化"} {
		if Md5Hex(s) != legacy(s) {
			t.Fatalf("Md5Hex(%q) diverges from legacy hand-rolled form — format stability broken", s)
		}
	}
}
