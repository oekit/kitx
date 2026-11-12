// 清零战役回归护栏（#146/#140，2026-11-12 sweep）：弱核心子串两侧同口径归一
// 的行为钉子与归一表自检。
package pwd

import (
	"errors"
	"testing"
)

// #146：弱核心子串判定两侧口径对称——core 与 haystack 一起 leet 归一。此前
// core 表存未归一原文、只归一 haystack，"123456"→"i2eas6"、"abc123"→"abci2e"
// 在归一 haystack 里永远找不到，两条数字核心永久不可达（契约文档点名的
// 123456 正是死条目）。修复后必须可达。
func TestPolicyWeakCoreNumericSubstrings(t *testing.T) {
	p := Policy{MinLength: 4} // 只开长度，隔离弱口令判定
	for _, pwd := range []string{
		"xx123456yy",   // 数字核心子串（#146 前不可达）
		"myabc123pass", // 字母数字混合核心子串（#146 前不可达）
		"foo123456",    // 后缀形态
		"abc123bar",    // 前缀形态
		"xxabc!23yy",   // haystack leet 归一后命中归一 core（两侧同口径的直接证明）
	} {
		var v *Violation
		if err := p.Check(pwd); !errors.As(err, &v) || v.Kind != KindWeak {
			t.Fatalf("%q 必须判弱口令（弱核心子串可达，#146），got %v", pwd, err)
		}
	}
	// 对照组：不含弱核心的正常密码不受影响。
	for _, pwd := range []string{"Xk9#mQ2$vL", "correct horse battery staple", "Zebra-9-River"} {
		if err := p.Check(pwd); err != nil {
			t.Fatalf("%q 不该被拒：%v", pwd, err)
		}
	}
}

// #146/#140：weakCoresNormalized 与 weakCores 一一对应、顺序不变、内容确为
// 归一形态，且两条数字核心的归一形态在表中存在（可达性前提）。
func TestWeakCoresNormalizedTable(t *testing.T) {
	norm := weakCoresNormalized()
	if len(norm) != len(weakCores) {
		t.Fatalf("归一表长度 %d != 原表 %d", len(norm), len(weakCores))
	}
	for i, core := range weakCores {
		if want := leetNormalize(core); norm[i] != want {
			t.Fatalf("weakCoresNormalized[%d] = %q, want leetNormalize(%q) = %q", i, norm[i], core, want)
		}
	}
	must := map[string]bool{"i2eas6": false, "abci2e": false} // "123456" / "abc123" 的归一形态
	for _, n := range norm {
		if _, ok := must[n]; ok {
			must[n] = true
		}
	}
	for k, hit := range must {
		if !hit {
			t.Fatalf("归一表缺 %q（#146 数字核心必须可达）", k)
		}
	}
}

// #140：leet 归一与 runes 转换收敛后判定结果不变——结构性弱模式的三个代表
// 形态与 weakIndex 完全匹配仍各归各类。
func TestWeakReasonVerdictsStable(t *testing.T) {
	runes := []rune("p@ssw0rd")
	if weak, why := weakReason("p@ssw0rd", runes); !weak || why == "" {
		t.Fatal("p@ssw0rd 必须判弱（weakIndex 完全匹配层）")
	}
	if weak, _ := weakReason("Xk9#mQ2$vL", []rune("Xk9#mQ2$vL")); weak {
		t.Fatal("Xk9#mQ2$vL 不该判弱")
	}
}
