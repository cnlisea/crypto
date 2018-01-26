package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

//SignWithRSA sign given encrypted data with RSA algorithm
func SignRSA(raw []byte, algorithm crypto.Hash, privateKey string) []byte {
	if raw == nil {
		return nil
	}

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	priv := privInterface.(*rsa.PrivateKey)
	var data []byte
	if algorithm == crypto.SHA1 {
		data = EncryptSHA(raw)
	} else {
		data = EncryptMD5(EncryptSHA(raw))
	}
	signed, err := rsa.SignPKCS1v15(rand.Reader, priv, algorithm, data)
	if err != nil {
		return nil
	}
	return signed
}

//VerifySignature verify whether the given signature is correct
func VerifySignature(raw []byte, signature string, algorithm crypto.Hash, publicKey string) bool {
	if raw == nil || signature == "" {
		return false
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return false
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pub := pubInterface.(*rsa.PublicKey)
	var data []byte
	if algorithm == crypto.SHA1 {
		data = EncryptSHA(raw)
	} else {
		data = EncryptMD5(EncryptSHA(raw))
	}
	err = rsa.VerifyPKCS1v15(pub, algorithm, data, DecryptBase64(signature))
	if err != nil {
		return false
	}
	return true
}
