package certos

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/julinox/funtls/tester"
	cert "github.com/julinox/funtls/tlssl/certificate"
	v1 "github.com/julinox/funtls/tlssl/certificate/v1"
	"github.com/sirupsen/logrus"
)

// fn certificateServer (certificate.go) failing.
// Issue is in the 'ModCerts' interface,
// Lets put it to the test and debug it...also, failing to
// the great John Carmack: Why am not using a debugger?
func TestEame(t *testing.T) {

	cpki := CertPKI()
	gg := cpki.GetBy(&cert.CertOpts{
		//DnsNames: []string{"server1.funssl.dev"},
		//DnsNames: []string{"server1.funssl.dev"},
		KeyAlgorithm:  x509.ECDSA,
		IgnoreExpired: true,
	})

	if gg != nil {
		fmt.Printf("---- Cert CNAME ---- | %v\n", gg.Subject.CommonName)
	}
	//fmt.Println(cpki.Print())
}

func CertPKI() cert.CertPKI {

	certos := []*cert.CertPath{
		{
			ChainPath: "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1chain.pem",
			KeyPath:   "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1key.pem",
		},
	}

	pki, err := v1.NewV1(tester.TestLogger(logrus.TraceLevel), certos)
	if err != nil {
		os.Exit(1)
	}

	return pki
}
