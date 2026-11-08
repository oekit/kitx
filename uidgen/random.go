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

// RandomString 从 alphabet 均匀采样 n 个字符（rune 语义：多字节 alphabet 产出
// 合法 UTF-8，输出恰含 n 个字符；#89）——拒绝采样消模偏差，无 mod 偏置。
//
// 入参防呆（全部当场 panic）：
//   - n <= 0 直接 panic（#88）：与 #50 对 RandomHex 的修法同口径——空串密钥是
//     最危险的缺省（「名义生成了、实际是空钥匙」），长度来自配置面时请在构造
//     期校验；
//   - alphabet 为空 panic；
//   - alphabet 字符数 > 256 panic（#52：拒绝采样 maxMultiple 归 0 ⇒ 死循环；
//     #89 起判据按 rune 数计，字节口径下的多字节大字符集不再被误伤）。
//
// 适用：带自定义字符集的短 ID/令牌。
func RandomString(alphabet string, n int) string {
	runes := checkStringArgs(alphabet, n)
	if len(runes) == 1 {
		out := make([]rune, n)
		for i := range out {
			out[i] = runes[0]
		}
		return string(out)
	}
	// 拒绝采样：256 % len 会造成高位取值偏差，丢弃 >= maxMultiple 的字节。
	maxMultiple := 256 - 256%len(runes)
	out := make([]rune, 0, n)
	buf := make([]byte, n+8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("uidgen: crypto/rand 不可用: " + err.Error())
		}
		for _, c := range buf {
			if int(c) < maxMultiple {
				out = append(out, runes[int(c)%len(runes)])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}

// checkStringArgs 校验 RandomString 的入参并返回 rune 形态的 alphabet（#89 起
// 全程按字符处理）：非法入参 panic 当场暴露，不静默降级。
func checkStringArgs(alphabet string, n int) []rune {
	if n <= 0 {
		panic(fmt.Sprintf("uidgen: RandomString 采样长度必须为正（got %d）——空串密钥是最危险的缺省，密钥/凭据场景漏个非正长度必须当场暴露（#88，对齐 #50）", n))
	}
	if len(alphabet) == 0 {
		panic("uidgen: 空 alphabet")
	}
	runes := []rune(alphabet)
	if len(runes) > 256 {
		panic(fmt.Sprintf("uidgen: alphabet 字符数 %d > 256，拒绝采样 maxMultiple 归 0 ⇒ RandomString 死循环（#52）——非法入参当场暴露（对齐 #50 哲学）", len(runes)))
	}
	return runes
}
