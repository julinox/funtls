package ciphersuites

import (
	"fmt"

	kx "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0xC02B struct {
	info *suiteBaseInfo
}

func EcdheEcdsaAes128GcmSha256(opts *suite.SuiteOpts) suite.Suite {

	var newSuite x0xC02B

	if opts == nil || opts.Pki == nil || opts.Lg == nil {
		return nil
	}

	newSuite.info = certPreselect(opts, ecdsaCertCheck)
	if len(newSuite.info.relatedcerts) == 0 {
		opts.Lg.Warnf("Suite registered (no certs): %v", newSuite.Name())
		return nil
	} else {
		opts.Lg.Infof("Suite registered: %v [%v]", newSuite.Name(),
			printCertNameType(newSuite.info.relatedcerts))
	}

	newSuite.info.certPki = opts.Pki
	return &newSuite
}

func (x *x0xC02B) ServerKX(data *kx.KXData) (*kx.KXParams, error) {

	var kxPms kx.KXParams

	if data == nil {
		return nil, fmt.Errorf("no data provided")
	}

	curve, err := kx.ECXKInit(&kx.ECKXConfig{
		SG:  data.SG,
		SA:  data.SA,
		Tax: names.SECP256R1,
	})

	if err != nil {
		return nil, err
	}

	ecSrvParams := kx.ECKXServerParams(curve)
	firma, err := kx.SignServerKXParams(ecSrvParams, data)
	if err != nil {
		return nil, err
	}

	kxPms.CurveParams = curve
	kxPms.Buffer = append(kxPms.Buffer, append(ecSrvParams, firma...)...)
	fmt.Printf("PrivateKey ECDHE: %x\n", curve.Private.Bytes())
	return &kxPms, nil
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

// - CN/SNI match
// - SG's curve allowed?
// - Can sign (ServerKeyExchange)
func (x *x0xC02B) CertMe(match *suite.CertMatch) []byte {

	for _, csc := range x.info.relatedcerts {
		chain := x.info.certPki.Get(csc.fingerPrint)
		if len(chain) == 0 {
			continue
		}

		if !matchSniSan(match.SNI, chain[0].DNSNames,
			chain[0].Subject.CommonName) {
			continue
		}

		if !x.info.certPki.SaSupport(match.SA, csc.fingerPrint) {
			continue
		}

		if err := validateChainSignatures(chain, match.SA); err != nil {
			continue
		}

		if len(match.SG) > 0 && !sgMatchEcdsa(chain[0], match.SG) {
			continue
		}

		return csc.fingerPrint
	}

	return nil
}
