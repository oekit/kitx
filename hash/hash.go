// Package hash 提供非密码学哈希助手（缓存键 / 幂等键 / 短唯一 code / 内容寻址）。
//
// ⚠️ 仅限非密码学场景：MD5 对抗碰撞能力早已不足，禁止用于凭据存储、签名、
// 安全校验——密码学摘要请用 pkg/encoding 的 Sha256/Sha256Hex 或 crypto 标准库。
//
// 为何收编 MD5（pkg#10）：2026-09-15 治理轮自 pkg/encoding 移除 Md5 家族
// （防弱哈希被误用到凭据场景），但两类正当场景被迫各业务仓手写——
//   - 缓存键生成：换哈希算法会使存量缓存键批量失效，无法平滑升级到 SHA-256；
//   - 短唯一 code：入库格式已有存量数据，格式即契约。
//
// 因此本包对 MD5 提供**格式稳定承诺**：算法与输出编码永不更换（升级哈希
// 等于新场景选型，不由本包承担）。
package hash

import (
	"crypto/md5"
	"encoding/hex"
)

// Md5Bytes 返回数据的 MD5 摘要（16 字节）。仅限非密码学场景（见包注释）。
func Md5Bytes(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

// Md5Hex 返回字符串的 MD5 十六进制摘要（32 字符小写）。
// 典型场景：请求参数序列化取缓存键、时间戳生成短唯一 code——
// 换算法会使存量键/码批量失效，故本函数对输出格式作稳定承诺。
func Md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
