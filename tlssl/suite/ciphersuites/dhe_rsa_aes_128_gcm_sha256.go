package ciphersuites

import (
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/julinox/funtls/tlssl/suite/dh"
)

type x0x009E struct {
	dhe dh.DiffieHellman
}

func NewDheRsaAes128GcmSha256() suite.Suite {

	return &x0x009E{
		dhe: dh.NewModDHClassic(),
	}
}

func (x *x0x009E) ID() uint16 {
	return 0x009E
}

func (x *x0x009E) Name() string {
	return suite.CipherSuiteNames[x.ID()]
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

func (x *x0x009E) AcceptsCert(sg, sa []uint16, cert *x509.Certificate) bool {

	if !x.acceptsCertSG(sg) {
		return false
	}

	if !x.acceptsCertSA(sa, cert) {
		return false
	}

	//fmt.Printf("%v | %v |s %v | %v\n", x.Name(), len(sg), len(sa), cert.Subject.CommonName)
	return true
}

func (x *x0x009E) acceptsCertSG(sg []uint16) bool {

	if len(sg) == 0 {
		return true // Fallback mode for classic DH
	}

	for _, g := range sg {
		if x.dhe.IsGroupSupported(g) {
			return true
		}
	}

	return false
}

func (x *x0x009E) acceptsCertSA(sa []uint16, cert *x509.Certificate) bool {

	fmt.Println(cert.SerialNumber)
	fmt.Println("DAJD AJDSOP JASPOD ASPODJ ASPJPOSA")
	return true
}
