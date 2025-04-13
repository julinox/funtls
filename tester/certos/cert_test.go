package certos

import (
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

	cNames := []string{"server1.funssl.dev", "localhost"}
	saAlgos := []uint16{0x403, 0x503, 0x603, 0x807, 0x808, 0x809, 0x80a, 0x80b,
		0x804, 0x805, 0x806, 0x401, 0x501, 0x601, 0x303, 0x301, 0x302, 0x402,
		0x502, 0x602}

	certos := loadCerts()
	for _, cn := range cNames {
		for _, sa := range saAlgos {
			//if cert := x.tCtx.Modz.Certs.GetByCriteria(sa, cn); cert != nil {
			/*if cert := x.tCtx.Certs.GetByCriteria(sa, cn); cert != nil {
				certs = append(certs, cert)
				break
			}*/

			certos.GetByCriteria(sa, cn)
			fmt.Println(cn, sa)
		}
	}

	t.Log("Hello, world!")
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

	certo, err := mx.NewModCerts2(tester.TestLogger(logrus.TraceLevel), cfg.Certs)
	if err != nil {
		os.Exit(1)
	}

	return certo
}
