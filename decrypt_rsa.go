package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

func rsaPublicKeyDecryptHelper(data []byte, publicKey string) ([]byte, error) {
	if len(data) > maxDataLen {
		return nil, ErrDataToLarge
	}

	block, _ := pem.Decode([]byte(publicKey))
	var (
		cert *x509.Certificate
		err  error
	)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	k := (cert.PublicKey.(*rsa.PublicKey).N.BitLen() + 7) / 8

	if k != len(data) {
		return nil, ErrDataLen
	}
	m := new(big.Int).SetBytes(data)

	if m.Cmp(cert.PublicKey.(*rsa.PublicKey).N) > 0 {
		return nil, ErrDataToLarge
	}

	m.Exp(m, big.NewInt(int64(cert.PublicKey.(*rsa.PublicKey).E)), cert.PublicKey.(*rsa.PublicKey).N)

	d := leftPad(m.Bytes(), k)

	if d[0] != 0 {
		return nil, ErrDataBroken
	}

	if d[1] != 0 && d[1] != 1 {
		return nil, ErrKeyPairDismatch
	}

	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil

}
