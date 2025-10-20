package certos

import (
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
	lg.Infof("GetBy() | CNAME %v (%v)", chain[0].Subject.CommonName, hexToPointString(fp[:8]))
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
		fmt.Printf("'%v' supports %v: %v\n", chain2[0].Subject.CommonName,
			names.SignHashAlgorithms[gg],
			cpki.SaSupport([]uint16{gg}, fp))
	}
}

func CertPKI() (cert.CertPKI, *logrus.Logger) {

	certos := []*cert.CertPath{
		{
			ChainPath: "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1chain.pem",
			KeyPath:   "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1key.pem",
		},
	}

	lg := tester.TestLogger(logrus.TraceLevel)
	pki, err := v1.NewV1(lg, certos)
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
