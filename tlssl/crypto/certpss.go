package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

type SubjectPublicKeyInfo struct {
	Algo                AlgorithmIdentifier
	SubjectPublicKeyBit asn1.BitString
}

type TbsCert struct {
	Version      asn1.RawValue `asn1:"optional,tag:0,explicit"`
	SerialNumber asn1.RawValue
	Signature    AlgorithmIdentifier
	Issuer       asn1.RawValue
	Validity     asn1.RawValue
	Subject      asn1.RawValue
	SubPKInfo    SubjectPublicKeyInfo
}

func ParseCertificate1(path string) (any, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	_, err = ParseCertificatePSS(block.Bytes)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func ParseCertificatePSS(der []byte) (*x509.Certificate, error) {

	var newCert *x509.Certificate
	var spk SubjectPublicKeyInfo

	newCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	if newCert.PublicKeyAlgorithm != 0 {
		return newCert, nil
	}

	_, err = asn1.Unmarshal(newCert.RawSubjectPublicKeyInfo, &spk)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling SPKI: %v", err)
	}

	if !spk.Algo.Algorithm.Equal(oidRSAPSS) {
		return newCert, fmt.Errorf("Unsupported public key algorithm")
	}

	return nil, fmt.Errorf("Actually, PSS certs not supported")
}
