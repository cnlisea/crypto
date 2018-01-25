package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"

	"bytes"

	"golang.org/x/crypto/pkcs12"
)

var (
	ErrIllegalParameter = errors.New("illegal parameter(s)")
	ErrDataLen          = errors.New("data length error")
	ErrDecryption       = errors.New("decryption error")
	ErrDataBroken       = errors.New("data broken, first byte is not zero")
	ErrDataToLarge      = errors.New("data is too large (len > 128) ")
	ErrKeyPairDismatch  = errors.New("data is not encrypted by the private key")
)

//EncryptBase64 encrypt given []byte with Base64 algorithm
func EncryptBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//Pfx EncryptRSA encrypt given data with RSA algorithm
// pfx加密
func PfxEncryptRSA(data []byte, pfxStr string, pfxPwd string) ([]byte, error) {
	if data == nil {
		return nil, ErrIllegalParameter
	}

	// 从pfx中获取私钥
	prk, _, err := pkcs12.Decode([]byte(pfxStr), pfxPwd)
	if nil != err {
		return nil, err
	}

	k := (prk.(*rsa.PrivateKey).N.BitLen()+7)/8 - 11
	var buf bytes.Buffer
	var b []byte
	// 分片加密, 通过私钥加密数据
	for i := 0; i < len(data); i += k {
		if i+k < len(data) {
			b = data[i : i+k]
		} else {
			b = data[i:]
		}
		b, err := priKeyEncrypt(rand.Reader, prk.(*rsa.PrivateKey), b)
		if nil != err {
			return nil, err
		}
		if _, err = buf.Write(b); nil != err {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

//private EncryptRSA encrypt given data with RSA algorithm
// 私钥加密
func PrivateEncryptRSA(data []byte, privateKey string) ([]byte, error) {
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

	k := (privInterface.(*rsa.PrivateKey).N.BitLen()+7)/8 - 11
	var buf bytes.Buffer
	var b []byte
	// 分片加密, 通过私钥加密数据
	for i := 0; i < len(data); i += k {
		if i+k < len(data) {
			b = data[i : i+k]
		} else {
			b = data[i:]
		}
		b, err := priKeyEncrypt(rand.Reader, prk.(*rsa.PrivateKey), b)
		if nil != err {
			return nil, err
		}
		if _, err = buf.Write(b); nil != err {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

//public EncryptRSA encrypt given data with RSA algorithm
// 公钥加密
func PublicEncryptRSA(data []byte, publicKey string) ([]byte, error) {
	if data == nil {
		return nil, ErrIllegalParameter
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, ErrIllegalParameter
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	encrypted := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += 117 {
		if i+117 < len(data) {
			partial, err1 := rsa.EncryptPKCS1v15(rand.Reader, pub, data[i:i+117])
			if err1 != nil {
				return nil, err1
			}
			encrypted = append(encrypted, partial...)
		} else {
			partial, err1 := rsa.EncryptPKCS1v15(rand.Reader, pub, data[i:])
			if err1 != nil {
				return nil, err1
			}
			encrypted = append(encrypted, partial...)
		}
	}
	return encrypted, nil
}

//EncryptMD5 encrypt given []byte with MD5 algorithm
func EncryptMD5(data []byte) []byte {
	if data == nil {
		return nil
	}
	encrypter := md5.New()
	encrypter.Write(data)
	return encrypter.Sum(nil)
}

//EncryptSHA encrypt given []byte with SHA algorithm
func EncryptSHA(data []byte) []byte {
	if data == nil {
		return nil
	}
	encypter := sha1.New()
	encypter.Write(data)
	return encypter.Sum(nil)
}

func BuildQuery(params map[string]string) string {
	array := make([]string, 0, len(params))
	for key, value := range params {
		if key == "" || value == "" {
			continue
		}
		array = append(array, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
	return string(strings.Join(array, "&"))
}
