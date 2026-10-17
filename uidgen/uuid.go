package uidgen

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// newV4 生成 RFC 4122 v4 UUID 的规范形式（小写、连字符分隔）。
// 16 字节 crypto/rand：第 7 字节高 4 位置版本号 4，第 9 字节高 2 位置
// variant 10，输出语义与 google/uuid 的 New().String() 逐字节一致。
func newV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("uidgen: crypto/rand 不可用: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// UUID 返回一个不带连字符的 UUID 字符串。
func UUID() string {
	return strings.ReplaceAll(newV4(), "-", "")
}

// ShortUUID 返回一个 16 位的短 UUID。
func ShortUUID() string {
	return UUID()[:16]
}

// UUIDToUpper 返回大写的 UUID 字符串。
func UUIDToUpper() string {
	return strings.ToUpper(UUID())
}

// ShortUUIDToUpper 返回大写的 16 位短 UUID。
func ShortUUIDToUpper() string {
	return UUIDToUpper()[:16]
}

// UUIDWithHyphen 返回带连字符的 UUID 字符串。
func UUIDWithHyphen() string {
	return newV4()
}
