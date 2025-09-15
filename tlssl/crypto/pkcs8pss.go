// This module provides support for parsing PKCS#8 private keys that use the
// rsaPSS algorithm (OID 1.2.840.113549.1.1.10), which is not supported by
// Go's crypto/x509 standard library.
//
// According to RFC 4055 §3.1, the RSASSA-PSS-params structure is a SEQUENCE of
// four optional fields: hashAlgorithm, maskGenAlgorithm, saltLength, and trailerField.
// Each field is tagged explicitly ([0] to [3]) and may be omitted entirely.
//
// When a field is missing, the following default values apply:
//
//   - hashAlgorithm:         sha1         (OID 1.3.14.3.2.26)
//   - maskGenAlgorithm:      mgf1SHA1     (OID 1.2.840.113549.1.1.8 with SHA1)
//   - saltLength:            20
//   - trailerField:          1
//
// Note that maskGenAlgorithm is an AlgorithmIdentifier and must be mgf1
// (OID 1.2.840.113549.1.1.8). Any other algorithm identifier is considered invalid.
// Its parameters field must contain another AlgorithmIdentifier that
// specifies the hash function used inside MGF1.
//
// If maskGenAlgorithm.parameters is absent, it is assumed to use the same hash
// algorithm as specified in hashAlgorithm (or SHA1 if that is also omitted).
//
// This module extracts these fields safely, applies the RFC-defined defaults when
// necessary, and performs strict validation on parameters (e.g., ensuring that
// algorithm parameters are NULL where required).

package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidMGF1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

var (
	pssDefaultTrailer    = 1
	pssDefaultSaltLength = 20
)

type PssParams struct {
	HashAlgorithm        asn1.ObjectIdentifier
	MaskGenAlgorithm     asn1.ObjectIdentifier
	MaskGenAlgorithmHash asn1.ObjectIdentifier
	SaltLength           int
	TrailerField         int
}

type PrivateKey struct {
	PrivKey any
	PSS     *PssParams
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type asn1PSSParams struct {
	HashAlgorithm    AlgorithmIdentifier `asn1:"optional,tag:0,explicit"`
	MaskGenAlgorithm AlgorithmIdentifier `asn1:"optional,tag:1,explicit"`
	SaltLength       int                 `asn1:"optional,tag:2,explicit"`
	TrailerField     int                 `asn1:"optional,tag:3,explicit"`
}

type pkcs8 struct {
	Version    int
	Algo       AlgorithmIdentifier
	PrivateKey []byte
}

// func ParsePKCS8PrivateKeyPSS(data []byte) (*PKCS8PSSKey, error) {
func ParsePKCS8PrivateKeyPSS(data []byte) (*PrivateKey, error) {

	var p8 pkcs8
	var key PrivateKey
	var asn1Pss asn1PSSParams

	_, err := asn1.Unmarshal(data, &p8)
	if err != nil {
		return nil, err
	}

	if !p8.Algo.Algorithm.Equal(oidRSAPSS) {
		key.PrivKey, err = x509.ParsePKCS8PrivateKey(data)
		if err != nil {
			return nil, err
		}

		key.PSS = nil
		return &key, nil
	}

	err = nil
	key.PrivKey, err = x509.ParsePKCS1PrivateKey(p8.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Lets get PSS params
	if len(p8.Algo.Parameters.FullBytes) == 0 {
		key.PSS = &PssParams{
			HashAlgorithm:        oidSHA1,
			MaskGenAlgorithm:     oidMGF1,
			MaskGenAlgorithmHash: oidSHA1,
			SaltLength:           pssDefaultSaltLength,
			TrailerField:         pssDefaultTrailer,
		}

		return &key, nil
	}

	_, err = asn1.Unmarshal(p8.Algo.Parameters.FullBytes, &asn1Pss)
	if err != nil {
		return nil, err
	}

	key.PSS, err = setPssParams(&asn1Pss)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func setPssParams(aPms *asn1PSSParams) (*PssParams, error) {

	var newPssParams PssParams
	var maskGenHashAlgo AlgorithmIdentifier

	newPssParams.HashAlgorithm = oidSHA1
	newPssParams.MaskGenAlgorithm = oidMGF1
	newPssParams.TrailerField = pssDefaultTrailer
	newPssParams.SaltLength = pssDefaultSaltLength
	if len(aPms.HashAlgorithm.Algorithm) != 0 {
		if !checkASN1Null(&aPms.HashAlgorithm.Parameters) {
			return nil, fmt.Errorf("hashAlgorithm with not NULL parameters")
		}

		newPssParams.HashAlgorithm = aPms.HashAlgorithm.Algorithm
	}

	newPssParams.MaskGenAlgorithmHash = newPssParams.HashAlgorithm
	if len(aPms.MaskGenAlgorithm.Algorithm) != 0 {
		if !aPms.MaskGenAlgorithm.Algorithm.Equal(oidMGF1) {
			return nil, fmt.Errorf("unsupported mask generation algorithm")
		}

		if len(aPms.MaskGenAlgorithm.Parameters.FullBytes) != 0 {
			_, err := asn1.Unmarshal(aPms.MaskGenAlgorithm.Parameters.FullBytes,
				&maskGenHashAlgo)
			if err != nil {
				return nil, err
			}

			if !checkASN1Null(&maskGenHashAlgo.Parameters) {
				return nil, fmt.Errorf("maskGenAlgorithm not NULL parameters")
			}

			newPssParams.MaskGenAlgorithmHash = maskGenHashAlgo.Algorithm
		}
	}

	if aPms.SaltLength != 0 {
		newPssParams.SaltLength = aPms.SaltLength
	}

	if aPms.TrailerField != 0 {
		newPssParams.TrailerField = aPms.TrailerField
	}

	return &newPssParams, nil
}

func checkASN1Null(val *asn1.RawValue) bool {

	if val == nil {
		return true
	}

	return len(val.Bytes) == 0 &&
		val.Class == 0 &&
		val.Tag == 5
}
