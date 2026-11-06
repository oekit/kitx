// crypto/rand 随机串生成（标识符/密钥面）：与 Snowflake（可预测、仅作 ID）分居——
// 密钥、一次性凭据、高熵标识符必须走本文件。
package uidgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

// RandomHex n 字节 crypto/rand 随机数的十六进制串（2n 字符）。
// nBytes <= 0 直接 panic（#50）：对标识符场景「非法长度=调用方 bug」，对密钥/
// 凭据场景静默空串是**最危险的缺省**——「名义生成了、实际是空钥匙」（空串做
// HMAC key / API token 落库后患无穷），与 RandomString 空 alphabet 的防呆哲学
// 对齐：非法入参启动即暴露好过静默降级。长度来自配置面时请在构造期校验。
//
// 适用：对象 ID、webhook secret、审批 HMAC 密钥等高熵标识符与密钥面。
func RandomHex(nBytes int) string {
	if nBytes <= 0 {
		panic("uidgen: RandomHex 字节数必须为正（got " + strconv.Itoa(nBytes) + "）——空串密钥是最危险的缺省，密钥/凭据场景漏个非正长度必须当场暴露")
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("uidgen: crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// RandomString 从 alphabet 均匀采样 n 个字符（拒绝采样消模偏差，无 mod 偏置）。
// alphabet 为空时 panic。适用：带自定义字符集的短 ID/令牌。
func RandomString(alphabet string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(alphabet) == 0 {
		panic("uidgen: 空 alphabet")
	}
	if len(alphabet) > 256 {
		panic(fmt.Sprintf("uidgen: alphabet 字节数 %d > 256，拒绝采样 maxMultiple 归 0 ⇒ RandomString 死循环（#52）——非法入参当场暴露（对齐 #50 哲学）", len(alphabet)))
	}
	if len(alphabet) == 1 {
		out := make([]byte, n)
		for i := range out {
			out[i] = alphabet[0]
		}
		return string(out)
	}
	// 拒绝采样：256 % len 会造成高位取值偏差，丢弃 >= maxMultiple 的字节。
	maxMultiple := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n+8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("uidgen: crypto/rand 不可用: " + err.Error())
		}
		for _, c := range buf {
			if int(c) < maxMultiple {
				out = append(out, alphabet[int(c)%len(alphabet)])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}
