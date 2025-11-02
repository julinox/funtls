package ciphersuites

import (
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0xC02B struct {
	signSchemes map[uint16]bool
}

func NewEcdheEcdsaAes128GcmSha256() suite.Suite {

	return &x0xC02B{
		signSchemes: map[uint16]bool{
			names.ECDSA_SECP256R1_SHA256: true,
			names.ECDSA_SECP384R1_SHA384: true,
			names.ECDSA_SECP521R1_SHA512: true,
		},
	}
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

func (x *x0xC02B) SignThis(msg1 []byte) []byte {
	return nil
}

func (x *x0xC02B) AcceptsCert(match *suite.CertMatch) error {

	if match == nil || match.Pki == nil {
		return fmt.Errorf("%v | no match params", x.Name())
	}

	if err := ecdhSGCertMatch(match); err != nil {
		return fmt.Errorf("%v | %v", x.Name(), err)
	}

	/*if err := ecdsaSACertMatch(match); err != nil {
		return fmt.Errorf("%v | %v", x.Name(), err)
	}*/

	return nil
}

// La curva de la pubkey debe estar en SG
func roleKxEcdhe(cert *x509.Certificate, sg []uint16) bool {

	if cert == nil {
		return false
	}

	groupName := getECGroupName(cert)
	if groupName == names.NOGROUP {
		return false
	}

	for _, g := range sg {
		if groupName == g {
			return true
		}
	}

	return false
}

func roleAuthEcdsa(cert *x509.Certificate) {

}
