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
	//Signature    asn1.RawValue
	Signature AlgorithmIdentifier
	Issuer    asn1.RawValue
	Validity  asn1.RawValue
	Subject   asn1.RawValue
	SubPKInfo SubjectPublicKeyInfo
}

type x509Cert struct {
	Tbs     TbsCert
	SigAlgo asn1.RawValue
	SigVal  asn1.RawValue
}

func POe(path string) (any, error) {

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
		fmt.Println("Error parsing certificate:", err)
		return nil, err
	}

	return nil, nil
}

func ParseCertificatePSS(der []byte) (*x509.Certificate, error) {

	//var pk rsa.PublicKey
	//var auxCert x509Cert
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
		fmt.Println("Error unmarshaling SPKI:", err)
		return nil, err
	}

	if !spk.Algo.Algorithm.Equal(oidRSAPSS) {
		return newCert, nil
	}

	fmt.Printf("Cert uses RSA-PSS with params: %v\n", spk.Algo.Parameters)
	fmt.Printf("spki1: %x\n", spk.Algo.Algorithm)
	fmt.Printf("spki2: %x\n", oidRSAPSS)
	/*fmt.Printf("ADSA %v\n", newCert.PublicKeyAlgorithm)
	fmt.Printf("%x\n", newCert.RawSubjectPublicKeyInfo)
	dataCopy := make([]byte, len(der))
	copy(dataCopy, der)
	_, err = asn1.Unmarshal(dataCopy, &auxCert)
	if err != nil {
		return nil, err
	}

	pkk := auxCert.Tbs.SubPKInfo.SubjectPublicKeyBit.Bytes
	_, err = asn1.Unmarshal(pkk, &pk)
	if err != nil {
		return nil, err
	}*/

	return newCert, nil
}
