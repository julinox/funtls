package certos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/julinox/funtls/tester"
	cert "github.com/julinox/funtls/tlssl/certpki"
	v1 "github.com/julinox/funtls/tlssl/certpki/v1"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

func TestSigner(t *testing.T) {

	var fingerprint []byte

	cpki, lg := CertPKI()
	fps := cpki.GetFingerPrints()
	for _, fp := range fps {
		fingerprint = fp
		break
	}

	csign := cpki.GetSigner(fingerprint)
	if csign == nil {
		lg.Errorf("nill crypto.Signer for '%x'", fingerprint)
		return
	}

	hashFn := crypto.SHA256.New()
	hashFn.Write([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFE})
	digest := hashFn.Sum(nil)
	signature, err := csign.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		lg.Errorf("Sign(): %v", err)
		return
	}

	lg.Info(signature)
}

func TestGet(t *testing.T) {

	cpki, lg := CertPKI()
	fmt.Println("---------- GetFingerPrints(), Get() ----------")
	fps := cpki.GetFingerPrints()
	for _, fp := range fps {
		chain := cpki.Get(fp)
		if len(chain) == 0 {
			lg.Errorf("No chain for '%v'", hexToPointString(fp[:6]))
			continue
		}

		lg.Infof("%v: %v (%v)", hexToPointString(fp[:6]),
			chain[0].Subject.CommonName, chain[0].PublicKeyAlgorithm)
	}

	fmt.Println("---------- GetAll() ----------")
	chains := cpki.GetAll()
	for _, chain := range chains {
		lg.Infof("%v (%v)", chain[0].Subject.CommonName,
			chain[0].PublicKeyAlgorithm)
	}
}

func TestSASupport(t *testing.T) {

	/*saList := []uint16{
		names.ECDSA_SECP256R1_SHA256,
		names.ECDSA_SECP384R1_SHA384,
		names.ECDSA_SECP521R1_SHA512,
		names.ED25519,
		names.ED448,
		names.RSA_PSS_PSS_SHA256,
		names.RSA_PSS_PSS_SHA384,
		names.RSA_PSS_PSS_SHA512,
		names.RSA_PKCS1_SHA256,
		names.RSA_PKCS1_SHA384,
		names.RSA_PKCS1_SHA512,
		names.RSA_PSS_RSAE_SHA256,
		names.RSA_PSS_RSAE_SHA384,
		names.RSA_PSS_RSAE_SHA512,
		names.SHA224_ECDSA,
		names.SHA224_RSA,
		names.SHA224_DSA,
		names.SHA256_DSA,
		names.SHA384_DSA,
		names.SHA512_DSA,
	}*/

	cpki, lg := CertPKI()
	fps := cpki.GetFingerPrints()
	for _, fp := range fps {
		chain := cpki.Get(fp)
		if len(chain) == 0 {
			lg.Errorf("No chain for %v", hexToPointString(fp[:6]))
			continue
		}

		saString := ""
		for k := range cpki.GetSaSupport(fp) {
			saString += fmt.Sprintf("%v,", names.SignatureAlgorithms[k])
		}

		lg.Infof("%v (%v) | SA = (%v)", chain[0].Subject.CommonName,
			certKeyName(chain[0]), saString)
		fmt.Println()
	}
}

func certKeyName(cert *x509.Certificate) string {

	if cert == nil {
		return ""
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519 - 256 bits"
	default:
		return ""
	}
}

func CertPKI() (cert.CertPKI, *logrus.Logger) {

	certos := []*cert.CertPath{
		{
			ChainPath: "/home/developer/certs/rsa/cert.pem",
			KeyPath:   "/home/developer/certs/rsa/key.pem",
		},
		/*{
			ChainPath: "/home/usery/ca/chains/server2chain.pem",
			KeyPath:   "/home/usery/ca/chains/private/server2chain.key",
		},
		{
			ChainPath: "/home/usery/ca/chains/server3chain.pem",
			KeyPath:   "/home/usery/ca/chains/private/server3chain.key",
		},*/
	}

	lg := tester.TestLogger(logrus.TraceLevel)
	pki, err := v1.NewCertPki(lg, certos)
	if err != nil {
		os.Exit(1)
	}

	return pki, lg
}

func hexToPointString(value []byte) string {

	parts := make([]string, len(value))
	for i, b := range value {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}

	return strings.Join(parts, ":")
}
