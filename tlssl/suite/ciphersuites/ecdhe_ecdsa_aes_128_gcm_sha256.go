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

// KX para ECDHE:
// La curva de la pubkey debe estar en SG
func ecdheKX(cert *x509.Certificate, sg []uint16) bool {

	if cert == nil {
		return false
	}

	/*for _, g := range sg {

	}*/
	return false
}

/*
func ecdsaSACertMatch(match *suite.CertMatch) error {

	if match == nil {
		return fmt.Errorf("nil suiteMatch")
	}

	chain := match.Pki.Get(match.FingerPrint)
	if len(chain) == 0 {
		return fmt.Errorf("no certificate chain")
	}

	name := fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
		chain[0].PublicKeyAlgorithm)

	if chain[0].PublicKeyAlgorithm != x509.ECDSA {
		return fmt.Errorf("public key not ECDSA | %v", name)
	}

	if !match.Pki.SaSupport(match.SA, match.FingerPrint) {
		return fmt.Errorf("unsupported SA list | %v", name)
	}

	// Esta firmado por ?
	fmt.Println("Firmado: ", chain[0].SignatureAlgorithm)
	return nil
}

*/

/*
1. Compatibilidad con los roles criptográficos
	1.1 Key Encipherment
		- Debe tener KeyUsage = keyEncipherment
		- La pubKey debe ser RSA

	1.2 Key Exchange (KX)
		- Si el KX es DHE:
			* Debe tener KeyUsage = keyAgreement
			* algorithm.parameter.G debe ser compatible con SG o SG-Legacy

		- Si el KX es ECDH:
			* Debe tener KeyUsage = keyAgreement
			* algorithm.parameter.? debe ser compatible con SG o SG-Legacy

		- Si el KX es ECDHE:
			* La pubKey del certificado NO participa en el KX
			* Si la suite es ECDHE, la curva usada en el KX debe estar en SG

	1.3 Signature (SKE o handshake)
		- Debe tener KeyUsage = digitalSignature
		- La pubKey debe coincidir con el algoritmo de firma/autenticación de la CS (RSA o ECDSA)
		- La pubKey debe poder firmar usando algún algoritmo de SA
		- Si la pubKey es ECDSA, su curva debe estar en SG

2. Validación de la cadena
	- Cada certificado en la cadena debe estar firmado con algún algoritmo en SA
	  (solo si el cliente envió SA; si no, se aplica modo legacy)
*/
