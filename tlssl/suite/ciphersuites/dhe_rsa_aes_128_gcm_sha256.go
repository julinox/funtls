package ciphersuites

import (
	"fmt"
	"strings"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0x009E struct {
	//inter *suiteInternal
	*suite.SuiteEnv
	relatedCerts [][]byte
}

func DheRsaAes128GcmSha256(env *suite.SuiteEnv) suite.Suite {

	var cNames []string
	var newSuite x0x009E

	if env == nil || env.Pki == nil || env.Lg == nil {
		return nil
	}

	newSuite.SuiteEnv = env
	fingerprints := env.Pki.GetFingerPrints()
	if len(fingerprints) <= 0 {
		return nil
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
		env.Lg.Warnf("Suite registered (no certs): %v", newSuite.Name())
		return nil
	}

	env.Lg.Infof("Suite registered: %v [%v]", newSuite.Name(),
		strings.Join(cNames, ","))
	return &newSuite
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

func (x *x0x009E) RelatedCerts() [][]byte {
	return x.relatedCerts
}

/*
func (x *x0x009E) ServerKX(data *kx.KXData) (*kx.KXParams, error) {

	return nil, nil
}
*/
