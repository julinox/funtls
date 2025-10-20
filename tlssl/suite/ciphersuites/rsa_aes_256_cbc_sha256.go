package ciphersuites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	pki "github.com/julinox/funtls/tlssl/certpki"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0x003D struct {
}

func NewRsaAes256CbcSha256() suite.Suite {
	return &x0x003D{}
}

func (x *x0x003D) ID() uint16 {
	return 0x003D
}

func (x *x0x003D) Name() string {
	return suite.CipherSuiteNames[x.ID()]
}

func (x *x0x003D) Info() *suite.SuiteInfo {

	return &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_CBC,
		Hash:        names.HASH_SHA256,
		HashSize:    sha256.Size,
		Cipher:      names.CIPHER_AES,
		KeySize:     32,
		KeySizeHMAC: 32,
		IVSize:      aes.BlockSize,
		Auth:        names.SIG_RSA,
		KeyExchange: names.KX_RSA,
	}
}

// Cipher and MAC
func (x *x0x003D) Cipher(ctx *suite.SuiteContext) ([]byte, error) {

	var err error

	err = x.basicCheck(ctx)
	if err != nil {
		return nil, err
	}

	return aesCBCEncrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x003D) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {

	if err := x.basicCheck(ctx); err != nil {
		return nil, err
	}

	return aesCBCDecrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x003D) MacMe(data, hashKey []byte) ([]byte, error) {

	if len(hashKey) != x.Info().KeySizeHMAC {
		return nil, fmt.Errorf("invalid hash key size (%v)", x.Name())
	}

	hmacHash := hmac.New(sha256.New, hashKey)
	hmacHash.Write(data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x003D) HashMe(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("nil/empty data")
	}

	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

func (x *x0x003D) AcceptsCert(sg, sa []uint16, cert *x509.Certificate) bool {

	fmt.Printf("%v | %v | %v | %v\n", x.Name(), len(sg), len(sa), cert.Subject.CommonName)
	return false
}

func (x *x0x003D) AcceptaCert(certPki pki.CertPKI) {

}

func (x *x0x003D) basicCheck(cc *suite.SuiteContext) error {

	if cc == nil || len(cc.Data) == 0 {
		return fmt.Errorf("nil/empty SuiteContext(%v)", x.Name())
	}

	if len(cc.Key) != x.Info().KeySize {
		return fmt.Errorf("invalid key size(%v)", x.Name())
	}

	if len(cc.IV) != aes.BlockSize {
		return fmt.Errorf("invalid IV size(%v)", x.Name())
	}

	return nil
}
