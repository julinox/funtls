package ciphersuites

import (
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0x009E struct {
}

func NewDHE_RSA_AES_128_GCM_SHA256() suite.Suite {
	return &x0x009E{}
}

func (x *x0x009E) ID() uint16 {
	return 0x009E
}

func (x *x0x009E) Name() string {
	return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
}

func (x *x0x009E) Info() *suite.SuiteInfo {

	return &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_AEAD,
		Hash:        names.HASH_SHA256,
		HashSize:    32,
		Cipher:      names.CIPHER_AES,
		KeySize:     16,
		KeySizeHMAC: 32,
		IVSize:      12,
		Auth:        names.SIG_RSA,
		KeyExchange: names.KX_DHE,
	}
}

func (x *x0x009E) Cipher(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0x009E Cipher not implemented")
}

func (x *x0x009E) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0x009E CipherNot not implemented")
}

func (x *x0x009E) MacMe(data, hashKey []byte) ([]byte, error) {
	return nil, fmt.Errorf("0x009E Macintosh not implemented")
}

func (x *x0x009E) HashMe(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("0x009E HashMe not implemented")
}
