package ciphersuites

import (
	"crypto/x509"
	"fmt"

	kex "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0x009E struct {
	*suite.SuiteEnv
	relatedCerts [][]byte
}

func DheRsaAes128GcmSha256(env *suite.SuiteEnv) (suite.Suite, error) {

	var cNames []string
	var newSuite x0x009E

	if env == nil || env.Pki == nil {
		return nil, fmt.Errorf("nil env/pki")
	}

	newSuite.SuiteEnv = env
	fingerprints := env.Pki.GetFingerPrints()
	if len(fingerprints) <= 0 {
		return nil, fmt.Errorf("")
	}

	newSuite.relatedCerts = make([][]byte, 0)
	for _, fp := range fingerprints {
		chain := env.Pki.Get(fp)
		if len(chain) == 0 || !rsaCertSignCheck(chain[0]) {
			continue
		}

		newSuite.relatedCerts = append(newSuite.relatedCerts, fp)
		cNames = append(cNames, chain[0].Subject.CommonName)
	}

	if len(newSuite.relatedCerts) == 0 {
		return nil, fmt.Errorf("no cert match")
	}

	return &newSuite, nil
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

func (x *x0x009E) Cipher(dst []byte, src []byte, ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0x009E Cipher not implemented")
}

func (x *x0x009E) CipherNot(dst []byte, src []byte, ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0x009E CipherNot not implemented")
}

func (x *x0x009E) MacMe(data, hashKey []byte) ([]byte, error) {
	return nil, fmt.Errorf("0x009E Macintosh not implemented")
}

func (x *x0x009E) HashMe(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("0x009E HashMe not implemented")
}

func (x *x0x009E) CertMe(ct *suite.CertCriteria) *suite.CertSelection {

	var selecto suite.CertSelection

	if ct == nil {
		return nil
	}

	for _, fp := range x.relatedCerts {
		chain := x.Pki.Get(fp)
		saSupport := x.Pki.GetSaSupport(fp)
		if len(chain) <= 0 {
			continue
		}

		if !checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageAny) &&
			!checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			continue
		}

		if !matchSniSan(ct.Sni, chain[0].DNSNames,
			chain[0].Subject.CommonName) {
			continue
		}

		if err := validateChainSignatures(chain, ct.SA); err != nil {
			continue
		}

		// Select SG
		for _, valG := range ct.SG {
			if kex.SupportedDHGroups[valG] {
				selecto.Group = valG
				break
			}
		}

		if selecto.Group == 0 {
			for k := range kex.SupportedDHGroups {
				selecto.Group = k
				break
			}
		}

		// Select SA
		for _, saa := range ct.SA {
			if saSupport[saa] {
				selecto.SignatureAlgorithm = saa
				break
			}
		}

		if selecto.SignatureAlgorithm == 0 {
			for k := range saSupport {
				selecto.SignatureAlgorithm = k
				break
			}
		}

		selecto.Fingerprint = fp
	}

	return &selecto
}

func (x *x0x009E) RelatedCerts() [][]byte {
	return x.relatedCerts
}

/*
func (x *x0x009E) CertMe(match *suite.CertMatch) []byte {

	for _, fp := range x.relatedCerts {
		chain := x.Pki.Get(fp)
		if len(chain) == 0 {
			continue
		}

		if !matchSniSan(match.SNI, chain[0].DNSNames,
			chain[0].Subject.CommonName) {
			continue
		}

		if !systema.SASupportAny(x.Pki.GetSaSupport(fp), match.SA) {
			continue
		}

		// y los grupos no los validas?????
		if err := validateChainSignatures(chain, match.SA); err != nil {
			continue
		}

		return fp
	}

	return nil
}
*/
