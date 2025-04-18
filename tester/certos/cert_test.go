package certos

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/julinox/funtls/server"
	"github.com/julinox/funtls/tester"
	mx "github.com/julinox/funtls/tlssl/modulos"
	"github.com/sirupsen/logrus"
)

// fn certificateServer (certificate.go) failing.
// Issue is in the 'ModCerts' interface,
// Lets put it to the test and debug it...also, failing to
// the great John Carmack: Why am not using a debugger?
func TestMe(t *testing.T) {

	var certs []*x509.Certificate

	cNames := []string{"server2.funssl.dev", "localhost"}
	saAlgos := []uint16{0x403, 0x503, 0x603, 0x807, 0x808, 0x809, 0x80a, 0x80b,
		0x804, 0x805, 0x806, 0x401, 0x501, 0x601, 0x303, 0x301, 0x302, 0x402,
		0x502, 0x602}

	certos := loadCerts()
	for _, cn := range cNames {
		for _, sa := range saAlgos {
			if cert := certos.GetByCriteria(sa, cn); cert != nil {
				certs = append(certs, cert)
				break
			}
		}
	}

	if len(certs) == 0 {
		t.Log("no certificate found")
		return
	}

	fmt.Println("Len #:", len(certs))
	fmt.Println("Cert:", certs[0].Subject.CommonName)
}

func TestMe2(t *testing.T) {

	certos := loadCerts()
	cc := certos.GetByCriteria(0, "localhost")
	if cc == nil {
		t.Log("no certificate found2")
		return
	}

	fmt.Println("Cert:", cc)
}

func loadCerts() mx.ModCerts {

	// Load all certificates and private keys
	cfg := &server.FunTLSCfg{
		Certs: []*mx.CertInfo{
			{
				PathCert: "/data/seagate/codigo/golang/workspace/tlscli/pki/server1chain.pem",
				PathKey:  "/data/seagate/codigo/golang/workspace/tlscli/pki/server1key.pem",
			},
		},
	}

	certo, err := mx.NewModCerts(tester.TestLogger(logrus.TraceLevel), cfg.Certs)
	if err != nil {
		os.Exit(1)
	}

	return certo
}
