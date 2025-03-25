package ciphersuites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"tlesio/tlssl/suite"
)

type x0x0035 struct {
}

func NewAES_256_CBC_SHA() suite.Suite {
	return &x0x0035{}
}

func (x *x0x0035) ID() uint16 {
	return 0x0035
}

func (x *x0x0035) Name() string {
	return "TLS_RSA_WITH_AES_256_CBC_SHA"
}

func (x *x0x0035) Info() *suite.SuiteInfo {
	return &suite.SuiteInfo{
		Mac:         suite.HMAC,
		CipherType:  suite.CIPHER_CBC,
		Hash:        suite.SHA1,
		HashSize:    sha1.Size,
		Cipher:      suite.AES,
		KeySize:     32,
		KeySizeHMAC: 20,
		IVSize:      aes.BlockSize,
		Auth:        suite.RSA,
		KeyExchange: suite.RSA,
	}
}

func (x *x0x0035) Cipher(ctx *suite.SuiteContext) ([]byte, error) {

	var err error

	err = x.basicCheck(ctx)
	if err != nil {
		return nil, err
	}

	return aesCBCEncrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x0035) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {

	if err := x.basicCheck(ctx); err != nil {
		return nil, err
	}

	return aesCBCDecrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x0035) MacMe(data, hashKey []byte) ([]byte, error) {

	if len(hashKey) != x.Info().KeySizeHMAC {
		return nil, fmt.Errorf("invalid key size(%v)", x.Name())
	}

	hmacHash := hmac.New(sha1.New, hashKey)
	hmacHash.Write(data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x0035) HashMe(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("nil/empty data(%v)", x.Name())
	}

	hash := sha1.New()
	hash.Write(data)
	return hash.Sum(nil), nil
}

func (x *x0x0035) basicCheck(cc *suite.SuiteContext) error {

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
