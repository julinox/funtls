package v1

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/julinox/funtls/tlssl/names"
)

func loadCertificateChain(path string) ([]*x509.Certificate, error) {

	var err error
	var certs []*x509.Certificate

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			newCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}

			certs = append(certs, newCert)
		}

		data = rest
	}

	return certs, nil
}

func loadPrivateKey(path string) (any, error) {

	var key any

	if path == "nil" {
		return nil, fmt.Errorf("empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}

func validateKeyPair(cert *x509.Certificate, key any) bool {

	if cert == nil || key == nil {
		return false
	}

	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)

	case *ecdsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)
	}

	return false
}

func certValidity(cert *x509.Certificate) bool {

	if cert == nil {
		return false
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false
	}

	if now.After(cert.NotAfter) {
		return false
	}

	return true
}

func certPreFlight(chain []*x509.Certificate) error {

	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	leaf := chain[0]
	if leaf == nil || leaf.PublicKey == nil {
		return fmt.Errorf("invalid leaf certificate")
	}

	if leaf.IsCA {
		return fmt.Errorf("leaf certificate is a CA certificate")
	}

	if !certValidity(leaf) {
		return fmt.Errorf("leaf certifcate is not valid at current time")
	}

	for i := 0; i+1 < len(chain); i++ {
		child, parent := chain[i], chain[i+1]
		if !parent.IsCA {
			return fmt.Errorf("parent certificate is not a CA certificate")
		}

		if parent.KeyUsage != 0 &&
			(parent.KeyUsage&x509.KeyUsageCertSign) == 0 {
			return fmt.Errorf("parent certificate does not allow signing")
		}

		if !certValidity(parent) {
			return fmt.Errorf("intermediate '%v' not valid at current time",
				parent.Subject.CommonName)
		}

		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("bad signature: child %v ← parent %v: %v",
				child.Subject.CommonName, parent.Subject.CommonName, err)
		}
	}

	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, eku := range leaf.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth {
				ok = true
				break
			}
		}

		if !ok {
			return fmt.Errorf("leaf doesn't have 'ExtKeyUsageServerAuth'")
		}
	}

	return nil
}

func isRSAPSSPublicKey(spki []byte) bool {

	pss := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	var aux struct {
		Algo   pkix.AlgorithmIdentifier
		BitStr asn1.BitString
	}

	if _, err := asn1.Unmarshal(spki, &aux); err != nil {
		return false
	}

	return aux.Algo.Algorithm.Equal(pss)
}

func certFingerPrint(cert *x509.Certificate) []byte {

	if cert == nil {
		return []byte{}
	}

	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func matchByname(dnsNames []string, certNames map[string]bool) bool {

	for _, name := range dnsNames {
		if certNames[name] {
			return true
		}
	}

	return false
}

func printSASupport(saSupport map[uint16]bool, separator string) string {

	var result string

	count := 0
	total := len(saSupport)
	for sa, supported := range saSupport {
		if supported {
			result += names.SignHashAlgorithms[sa]
			count++
			if count < total {
				result += separator
			}
		}
	}

	return result
}

// Print hex like "AA:BB..."
func hexToPointString(value []byte) string {

	parts := make([]string, len(value))
	for i, b := range value {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}

	return strings.Join(parts, ":")
}
