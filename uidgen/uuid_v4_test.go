package uidgen

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestUUIDV4Bits 验证手写 v4 的版本号与 variant 位：这是与 RFC 4122
// 兼容的核心不变量，也是对 google/uuid 语义对齐的回归锚点。
func TestUUIDV4Bits(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := UUIDWithHyphen()
		if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("malformed UUID layout: %s", id)
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil {
			t.Fatalf("not hex: %s", id)
		}
		if raw[6]>>4 != 4 {
			t.Fatalf("version nibble = %x, want 4: %s", raw[6]>>4, id)
		}
		if raw[8]>>6 != 2 {
			t.Fatalf("variant bits = %d, want 2 (10xx): %s", raw[8]>>6, id)
		}
	}
}
