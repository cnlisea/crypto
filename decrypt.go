package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

const (
	//MaxDataLen max data single decrypt data length.
	maxDataLen = 128
)

//DecryptBase64 decrypt given string with Base64 algorithm
func DecryptBase64(data string) []byte {
	if data == "" {
		return nil
	}
	decrypted, _ := base64.StdEncoding.DecodeString(data)
	return decrypted
}

//Public DecryptRSA decrypt given data with RSA algorithm
// 公钥解密
func PublicDecryptRSA(data []byte, publicKey string) ([]byte, error) {
	if nil == data {
		return nil, ErrIllegalParameter
	}

	var (
		err       error
		plainText []byte
	)

	buf := &bytes.Buffer{}

	for len(data) >= maxDataLen {

		dataStub := data[:maxDataLen]
		data = data[maxDataLen:]

		plainText, err = rsaPublicKeyDecryptHelper(dataStub, publicKey)
		if err != nil {
			break
		}
		buf.Write(plainText)
	}

	return buf.Bytes(), nil

}

//DecryptRSA decrypt given []byte with RSA algorithm
// 私钥加密
func PrivateDecryptRSA(data []byte, privateKey string) ([]byte, error) {
	if data == nil {
		return nil, ErrIllegalParameter
	}

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, ErrIllegalParameter
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv := privInterface.(*rsa.PrivateKey)
	decrypted := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += 128 {
		if i+128 < len(data) {
			partial, err1 := rsa.DecryptPKCS1v15(rand.Reader, priv, data[i:i+128])
			if err1 != nil {
				return nil, err1
			}
			decrypted = append(decrypted, partial...)
		} else {
			partial, err1 := rsa.DecryptPKCS1v15(rand.Reader, priv, data[i:])
			if err1 != nil {
				return nil, err1
			}
			decrypted = append(decrypted, partial...)
		}
	}
	return decrypted, nil
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
// copy from crypto/rsa/rsa.go.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
