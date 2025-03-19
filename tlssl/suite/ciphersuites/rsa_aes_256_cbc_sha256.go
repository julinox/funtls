package ciphersuites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"tlesio/tlssl/suite"
)

type x0x003D struct {
}

func NewAES_256_CBC_SHA256() suite.Suite {

	return &x0x003D{}
}

func (x *x0x003D) ID() uint16 {
	return 0x003D
}

func (x *x0x003D) Name() string {
	return "TLS_RSA_WITH_AES_256_CBC_SHA256"
}

func (x *x0x003D) Info() *suite.SuiteInfo {
	return &suite.SuiteInfo{
		Mac:         suite.HMAC,
		CipherType:  suite.CIPHER_CBC,
		Hash:        suite.SHA256,
		HashSize:    sha256.Size,
		Cipher:      suite.AES,
		KeySize:     32,
		KeySizeHMAC: 32,
		IVSize:      aes.BlockSize,
		Auth:        suite.RSA,
		KeyExchange: suite.RSA,
	}
}

// Cipher and MAC
func (x *x0x003D) Cipher(sc *suite.SuiteContext) ([]byte, error) {

	var err error

	err = x.basicCheck(sc)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (x *x0x003D) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {

	if err := x.basicCheck(ctx); err != nil {
		return nil, err
	}

	return aesCBCDecrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x003D) MacMe(data, hashKey []byte) ([]byte, error) {

	if len(hashKey) != x.Info().KeySizeHMAC {
		return nil, fmt.Errorf("nil/empty MAC Key")
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
