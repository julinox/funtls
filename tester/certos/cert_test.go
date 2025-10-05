package certos

import (
	"fmt"
	"os"
	"testing"

	"crypto/aes"
	"crypto/sha256"

	"github.com/julinox/funtls/server"
	"github.com/julinox/funtls/tester"
	mx "github.com/julinox/funtls/tlssl/modulos"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/sirupsen/logrus"
)

// fn certificateServer (certificate.go) failing.
// Issue is in the 'ModCerts' interface,
// Lets put it to the test and debug it...also, failing to
// the great John Carmack: Why am not using a debugger?
func TestMe(t *testing.T) {

	var opts mx.CertOpts
	//var certs []*x509.Certificate
	//var suiteInfo SuiteInfo

	//cNames := []string{"server2.funssl.dev", "localhost"}
	/*saAlgos := []uint16{0x403, 0x503, 0x603, 0x807, 0x808, 0x809, 0x80a, 0x80b,
	0x804, 0x805, 0x806, 0x401, 0x501, 0x601, 0x303, 0x301, 0x302, 0x402,
	0x502, 0x602}*/
	saAlgos := []uint16{
		names.ECDSA_SECP256R1_SHA256,
		names.ECDSA_SECP384R1_SHA384,
		names.ECDSA_SECP521R1_SHA512,
		names.RSA_PSS_PSS_SHA256,
		names.RSA_PKCS1_SHA512,
		//names.RSA_PKCS1_SHA256,
		//names.RSA_PKCS1_SHA384,
		names.SHA224_ECDSA,
	}

	modC := modCert()
	if modC == nil {
		t.Log("modC is nil")
		return
	}

	opts.Sni = ""
	//opts.Sni = "pepito.com"
	//opts.Sni = "server1.funssl.dev"
	opts.SA = saAlgos
	opts.CsInfo = &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_CBC,
		Hash:        names.HASH_SHA256,
		HashSize:    sha256.Size,
		Cipher:      names.CIPHER_AES,
		KeySize:     32,
		KeySizeHMAC: 32,
		IVSize:      aes.BlockSize,
		Auth:        names.SIG_ECDSA,
		KeyExchange: names.KX_DHE,
	}

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
