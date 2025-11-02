package certos

import (
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/julinox/funtls/tester"
	cert "github.com/julinox/funtls/tlssl/certpki"
	v1 "github.com/julinox/funtls/tlssl/certpki/v1"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

// fn certificateServer (certificate.go) failing.
// Issue is in the 'ModCerts' interface,
// Lets put it to the test and debug it...also, failing to
// the great John Carmack: Why am not using a debugger?
func TestEame(t *testing.T) {

	cpki, lg := CertPKI()
	chain := cpki.GetBy(&cert.CertOpts{
		//DnsNames: []string{"server1.funssl.dev"},
		//DnsNames: []string{"server1.funssl.dev"},
		KeyAlgorithm: x509.ECDSA,
		//KeyAlgorithm:  x509.RSA,
		IgnoreExpired: true,
	})

	if len(chain) == 0 {
		return
	}

	fp := cpki.FingerPrint(chain[0])
	lg.Infof("GetBy() | CNAME %v (%v)", chain[0].Subject.CommonName,
		hexToPointString(fp[:8]))
	chain2 := cpki.Get(fp)
	for _, c := range chain2 {
		lg.Infof("Get() | %v", c.Subject.CommonName)
	}

	// SA Support
	//algoName := names.ECDSA_SECP384R1_SHA384
	sa := []uint16{
		names.ECDSA_SECP384R1_SHA384,
		names.ECDSA_SECP521R1_SHA512,
		names.RSA_PSS_RSAE_SHA384,
		names.ECDSA_SECP256R1_SHA256,
	}

	for _, gg := range sa {
		lg.Infof("'%v' supports %v: %v", chain2[0].Subject.CommonName,
			names.SignHashAlgorithms[gg],
			cpki.SaSupport([]uint16{gg}, fp))
	}

	// Key
	key := cpki.GetCertPKey(fp)
	if key != nil {
		lg.Info("Key founded")
	}
}

func TestFML(t *testing.T) {

	/*cpki, lg := CertPKI()
	chain := cpki.GetBy(&cert.CertOpts{
		//DnsNames: []string{"server1.funssl.dev"},
		//DnsNames: []string{"server1.funssl.dev"},
		KeyAlgorithm: x509.ECDSA,
		//KeyAlgorithm:  x509.RSA,
		IgnoreExpired: true,
	})

	if lg == nil {
		fmt.Println("--- No logger ---")
		return
	}

	if len(chain) == 0 {
		lg.Error("No chain to operate with")
		return
	}

	//fp := cpki.FingerPrint(chain[0])
	sa := []uint16{
		//names.RSA_PKCS1_SHA256,
		names.RSA_PSS_RSAE_SHA256,

		//names.RSA_PKCS1_SHA384,
		//names.RSA_PSS_RSAE_SHA384,

		//names.RSA_PKCS1_SHA512,
		//names.RSA_PSS_RSAE_SHA512,

		names.ECDSA_SECP256R1_SHA256,
		names.ECDSA_SECP384R1_SHA384,
		//names.ECDSA_SECP521R1_SHA512,
	}

	err := css.ValidateChainSignatures(chain, sa)
	if err != nil {
		lg.Errorf("%v", err)
		return
	}

	lg.Info("Chain OK!")*/
}

func GetCertoCurva(cert *x509.Certificate) uint16 {

	if cert == nil {
		return 0
	}

	return 0
}

func CertPKI() (cert.CertPKI, *logrus.Logger) {

	certos := []*cert.CertPath{
		{
			ChainPath: "/home/usery/ca/chains/server2chain.pem",
			KeyPath:   "/home/usery/ca/funtls/private/server2funtlsdev.key",
		},
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
