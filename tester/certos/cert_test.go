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
func TestEcdheEcdsa(t *testing.T) {

	var opts mx.CertOpts

	opts.Sni = ""
	opts.SG = supportedGroups
	opts.SA = saAlgos1
	opts.CsInfo = csEcdheEcdsa
	modC := modCert()
	if modC == nil {
		t.Log("modC is nil")
		return
	}

	chain := modC.GetHSCert(&opts)
	if len(chain) == 0 {
		t.Log("No certo")
		return
	}

	fmt.Printf("Match: %v\n", chain[0].Subject.CommonName)
}

func TestDheEcdsa(t *testing.T) {

	var opts mx.CertOpts

	modC := modCert()
	if modC == nil {
		t.Log("modC is nil")
		return
	}

	opts.Sni = ""
	opts.CsInfo = csDheEcdsa
	opts.SA = saAlgos1
	chain := modC.GetHSCert(&opts)
	if len(chain) == 0 {
		t.Log("No certo")
		return
	}

	fmt.Printf("Match: %v\n", chain[0].Subject.CommonName)
}

func modCert() mx.ModCerts {

	// Load all certificates and private keys
	cfg := &server.FunTLSCfg{
		Certs: []*mx.CertInfo{
			{
				PathCert: "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1chain.pem",
				PathKey:  "/data/seagate/codigo/golang/workspace/funtls/cmd/pki3/server1key.pem",
			},
		},
	}

	mod, err := mx.NewModCerts(tester.TestLogger(logrus.TraceLevel), cfg.Certs)
	if err != nil {
		os.Exit(1)
	}

	return mod
}
