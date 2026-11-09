package jwt

import (
	"testing"
)

// #96：MarshalKeyPairPEM 空值检查对称化——此前只查 Private 不查 Public，缺
// Public 时 nil 指针 panic（x509.MarshalPKIXPublicKey 解引用 pub.N），而手动
// 构造 KeyPair（从已有私钥文件加载、只用一半做测试）是合法用法。
func TestMarshalKeyPairPEMRejectsPartialKeyPair(t *testing.T) {
	kp := newTestKeyPair(t)

	// 缺 Public：必须返回 error 而非 panic。
	privOnly := &KeyPair{Private: kp.Private}
	privPEM, pubPEM, err := MarshalKeyPairPEM(privOnly)
	if err == nil {
		t.Fatalf("MarshalKeyPairPEM(priv-only) must return error, got priv=%d pub=%d", len(privPEM), len(pubPEM))
	}
	if privPEM != "" || pubPEM != "" {
		t.Fatalf("MarshalKeyPairPEM(priv-only) must return empty PEMs on error, got %q %q", privPEM, pubPEM)
	}

	// 缺 Private：既有口径不变（返回 error）。
	pubOnly := &KeyPair{Public: kp.Public}
	if _, _, err := MarshalKeyPairPEM(pubOnly); err == nil {
		t.Fatal("MarshalKeyPairPEM(pub-only) must return error")
	}

	// kp 为 nil：既有口径不变（返回 error）。
	if _, _, err := MarshalKeyPairPEM(nil); err == nil {
		t.Fatal("MarshalKeyPairPEM(nil) must return error")
	}

	// 完整 KeyPair：正常路径回归（往返可用）。
	gotPriv, gotPub, err := MarshalKeyPairPEM(kp)
	if err != nil {
		t.Fatalf("MarshalKeyPairPEM(complete) error = %v", err)
	}
	priv, err := ParsePrivateKey([]byte(gotPriv))
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	pub, err := ParsePublicKey([]byte(gotPub))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Fatal("public key does not match private key")
	}
}
