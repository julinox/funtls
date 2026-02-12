package ciphersuites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"

	kx "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0x0035 struct {
	info *suiteBaseInfo
}

func RsaAes256CbcSha(opts *suite.SuiteOpts) suite.Suite {

	var newSuite x0x0035

	if opts == nil || opts.Pki == nil || opts.Lg == nil {
		return nil
	}

	newSuite.info = certPreselect(opts, rsaCertCheck)
	if len(newSuite.info.relatedcerts) == 0 {
		opts.Lg.Warnf("Suite registered (no certs): %v", newSuite.Name())
	} else {
		opts.Lg.Infof("Suite registered: %v [%v]", newSuite.Name(),
			printCertNameType(newSuite.info.relatedcerts))
	}

	newSuite.info.certPki = opts.Pki
	return &newSuite
}

func (x *x0x0035) ID() uint16 {
	return 0x0035
}

func (x *x0x0035) Name() string {
	return suite.CipherSuiteNames[x.ID()]
}

func (x *x0x0035) Info() *suite.SuiteInfo {

	return &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_CBC,
		Hash:        names.HASH_SHA1,
		HashSize:    sha1.Size,
		Cipher:      names.CIPHER_AES,
		KeySize:     32,
		KeySizeHMAC: 20,
		IVSize:      aes.BlockSize,
		Auth:        names.SIG_RSA,
		KeyExchange: names.KX_RSA,
	}
}

func (x *x0x0035) Cipher(ctx *suite.SuiteContext) ([]byte, error) {

	var err error

	err = x.basicCheck(ctx)
	if err != nil {
		return nil, err
	}

	return aesCBCEncrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x0035) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {

	if err := x.basicCheck(ctx); err != nil {
		return nil, err
	}

	return aesCBCDecrypt(ctx.Data, ctx.Key, ctx.IV)
}

func (x *x0x0035) MacMe(data, hashKey []byte) ([]byte, error) {

	if len(hashKey) != x.Info().KeySizeHMAC {
		return nil, fmt.Errorf("invalid key size(%v)", x.Name())
	}

	hmacHash := hmac.New(sha1.New, hashKey)
	hmacHash.Write(data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x0035) HashMe(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("nil/empty data(%v)", x.Name())
	}

	hash := sha1.New()
	hash.Write(data)
	return hash.Sum(nil), nil
}

func (x *x0x0035) CertMe(match *suite.CertMatch) []byte {

	for _, csc := range x.info.relatedcerts {
		chain := x.info.certPki.Get(csc.fingerPrint)
		if len(chain) == 0 {
			continue
		}

		if !matchSniSan(match.SNI, chain[0].DNSNames,
			chain[0].Subject.CommonName) {
			continue
		}

		if err := validateChainSignatures(chain, match.SA); err != nil {
			continue
		}

		return csc.fingerPrint
	}

	return nil
}

func (x *x0x0035) basicCheck(cc *suite.SuiteContext) error {

	if cc == nil || len(cc.Data) == 0 {
		return fmt.Errorf("nil/empty SuiteContext(%v)", x.Name())
	}

	if len(cc.Key) != x.Info().KeySize {
		return fmt.Errorf("invalid key size(%v)", x.Name())
	}

	if len(cc.IV) != aes.BlockSize {
		return fmt.Errorf("invalid IV size(%v)", x.Name())
	}

	return nil
}

func (x *x0x0035) ServerKX(data *kx.KXData) ([]byte, error) {
	return nil, nil
}
