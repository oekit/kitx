package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair 持有 RS256 的密钥对。
type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// GenerateKeyPair 生成 RSA 密钥对（bits < 2048 时按 2048 处理）。
func GenerateKeyPair(bits int) (*KeyPair, error) {
	if bits < 2048 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA 密钥对: %w", err)
	}
	return &KeyPair{Private: key, Public: &key.PublicKey}, nil
}

// MarshalKeyPairPEM 把密钥对编为 PEM（私钥 PKCS#1，公钥 PKIX）。
//
// 空值检查对称（#96）：Private 与 Public 任一缺失都返回 error——手动构造
// KeyPair 是合法用法（从已有私钥文件加载、只用一半做测试），缺 Public 时此前
// 直接 nil 指针 panic（x509.MarshalPKIXPublicKey 解引用 pub.N），与同包
// NewSymmetric/GenerateKeyPair 的「非法输入返回 error」风格不一致。
func MarshalKeyPairPEM(kp *KeyPair) (privPEM, pubPEM string, err error) {
	if kp == nil || kp.Private == nil {
		return "", "", fmt.Errorf("缺少私钥")
	}
	if kp.Public == nil {
		return "", "", fmt.Errorf("缺少公钥")
	}
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(kp.Private)}
	pubBytes, err := x509.MarshalPKIXPublicKey(kp.Public)
	if err != nil {
		return "", "", fmt.Errorf("编码公钥: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	return string(pem.EncodeToMemory(privBlock)), string(pem.EncodeToMemory(pubBlock)), nil
}

// ParsePrivateKey 解析 PEM 私钥（PKCS#1 / PKCS#8）。
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("私钥不是合法的 PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	rsaKey, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("私钥不是 RSA 私钥")
	}
	return rsaKey, nil
}

// ParsePublicKey 解析 PEM 公钥（PKIX / PKCS#1），也接受 X.509 证书。
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("公钥不是合法的 PEM")
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("证书公钥不是 RSA 公钥")
	}
	anyKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %w", err)
	}
	rsaKey, ok := anyKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是 RSA 公钥")
	}
	return rsaKey, nil
}
