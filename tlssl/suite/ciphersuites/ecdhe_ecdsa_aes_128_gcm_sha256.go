package ciphersuites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

func (x *x0xC02B) AcceptsCert(match *suite.SuiteMatch) bool {

	if match == nil || match.Pki == nil {
		return false
	}

	chain := match.Pki.Get(match.FingerPrint)
	if len(chain) == 0 {
		return false
	}

	if !ecdsaGroupSupport(chain[0], match.SG) {
		return false
	}

	if chain[0].PublicKeyAlgorithm != x509.ECDSA {
		return false
	}

	if !match.Pki.SaSupport(match.SA, match.FingerPrint) {
		return false
	}

	// Esta firmado por
	return false
}

func ecdsaGroupSupport(cert *x509.Certificate, sg []uint16) bool {

	var certGroup uint16

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	if len(sg) == 0 {
		return false
	}

	switch publicKey.Curve {
	case elliptic.P224():
		certGroup = names.SECP224R1
	case elliptic.P256():
		certGroup = names.SECP256R1
	case elliptic.P384():
		certGroup = names.SECP384R1
	case elliptic.P521():
		certGroup = names.SECP521R1
	default:
		return false
	}

	for _, g := range sg {
		if g == certGroup {
			return true
		}
	}

	return false
}
