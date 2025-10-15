package ciphersuites

import (
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0xC02B struct {
}

func NewEcdheEcdsaAes128GcmSha256() suite.Suite {
	return &x0xC02B{}
}

func (x *x0xC02B) ID() uint16 {
	return 0xC02B
}

func (x *x0xC02B) Name() string {
	return suite.CipherSuiteNames[x.ID()]
}

func (x *x0xC02B) Info() *suite.SuiteInfo {

	return &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_AEAD,
		Hash:        names.HASH_SHA256,
		HashSize:    32,
		Cipher:      names.CIPHER_AES,
		KeySize:     16,
		KeySizeHMAC: 32,
		IVSize:      12,
		Auth:        names.SIG_ECDSA,
		KeyExchange: names.KX_ECDHE,
	}
}

func (x *x0xC02B) Cipher(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B Cipher not implemented")
}

func (x *x0xC02B) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B CipherNot not implemented")
}

func (x *x0xC02B) MacMe(data, hashKey []byte) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B Macintosh not implemented")
}

func (x *x0xC02B) HashMe(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B HashMe not implemented")
}

func (x *x0xC02B) AcceptsCert(sg, sa []uint16, cert *x509.Certificate) bool {

	fmt.Printf("%v | %v | %v | %v\n", x.Name(), len(sg), len(sa), cert.Subject.CommonName)
	return false
}
