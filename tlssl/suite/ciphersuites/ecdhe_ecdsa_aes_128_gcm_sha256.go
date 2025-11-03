package ciphersuites

import (
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type csCert struct {
	group       uint16
	fingerPrint []byte
}

type x0xC02B struct {
	isClient bool
	certs    []*csCert
}

func EcdheEcdsaAes128GcmSha256(opts *suite.SuiteOpts) suite.Suite {

	var newSuite x0xC02B
	var certNames []string

	if opts == nil || opts.Pki == nil || opts.Lg == nil {
		return nil
	}

	newSuite.certs = make([]*csCert, 0)
	if opts.IsClient {
		newSuite.isClient = true
		return &newSuite
	}

	fingerPrints := opts.Pki.GetFingerPrints()
	if len(fingerPrints) == 0 {
		return nil
	}

	for _, fp := range fingerPrints {
		chain := opts.Pki.Get(fp)
		if len(chain) == 0 || chain[0].PublicKeyAlgorithm != x509.ECDSA {
			continue
		}

		if chain[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			continue
		}

		if !checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageAny) &&
			!checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			continue
		}

		groupName := ecGroupName(chain[0])
		if groupName == names.NOGROUP {
			continue
		}

		aux := fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
			chain[0].PublicKeyAlgorithm)
		certNames = append(certNames, aux)
		newSuite.certs = append(newSuite.certs, &csCert{groupName, fp})
	}

	opts.Lg.Warnf("%v: %v", newSuite.Name(), certNames)
	return &newSuite
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

	chain := match.Pki.Get(match.FingerPrint)
	if len(chain) == 0 {
		return fmt.Errorf("%v | no chain", x.Name())
	}

	certName := fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
		chain[0].PublicKeyAlgorithm)

	if !roleKxEcdhe(chain[0], match.SG) {
		return fmt.Errorf("%v | no role", certName)
	}

	if err := roleAuthEcdsa(chain[0], match.SA, match.SG); err != nil {
		return fmt.Errorf("%v | %v", certName, err)
	}

	return nil
}

// Si SA = [] entonces se acepta siempre que la curva sea EC
//
// -Debe tener KeyUsage = digitalSignature
// -La pubKey debe coincidir con el algoritmo de firma/autenticación
// de la CS (RSA o ECDSA)
// - Si la pubKey es ECDSA, su curva debe estar en SG si len(SG) > 0
// - La pubKey debe poder firmar usando algún algoritmo de SA
func roleAuthEcdsa(cert *x509.Certificate, sa, sg []uint16) error {

	var err error

	if cert == nil {
		return nil
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("no KeyUsageDigitalSignature")
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return fmt.Errorf("pubkey not ecdsa")
	}

	groupName := ecGroupName(cert)
	if !sgCheck(groupName, sg) {
		return fmt.Errorf("cert's curve not within SG")
	}

	return err
}

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
