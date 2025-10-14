package modulos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

// A certificate by itself does not define whether the Key Exchange (KX)
// uses static (EC)DH or ephemeral (EC)DHE. That is defined by the cipher suite.
// In static (EC)DH, the same long-term private key is reused in every key exchange.
// This implies:
// - The server must already possess the long-term (EC)DH private key
// - The certificate public key must correspond to that static key
// Therefore, the certificate must include KeyUsage keyAgreement for static (EC)DH.
//
// In (EC)DHE, the server generates a fresh ephemeral key per handshake,
// and the certificate is only used to sign the ServerKeyExchange parameters.
// KeyAgreement is not required; DigitalSignature is enough.
func getHSCertKX(opts *CertOpts, certo *x509.Certificate) bool {

	if opts == nil || certo == nil {
		return false
	}

	//cert := p.certChain[0]
	switch opts.CsInfo.KeyExchange {
	case names.KX_RSA:
		if certo.KeyUsage&x509.KeyUsageKeyEncipherment == 0 ||
			certo.PublicKeyAlgorithm != x509.RSA {
			return false
		}

	case names.KX_DH:
		fallthrough
	case names.KX_DHE:
		fmt.Println("----------------------HSCERTKXDHE---------------------")

	case names.KX_ECDH:
		fallthrough
	case names.KX_ECDHE:
		return getHSCertkxEcdhe(opts, certo)

	default:
		return false
	}

	return true
}

// Does given certificate's curve match against a list of supported groups?
func getHSCertkxEcdhe(opts *CertOpts, certo *x509.Certificate) bool {

	var curveId uint16

	sgs := opts.SG
	if len(sgs) == 0 {
		return false
	}

	key, ok := certo.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	if opts.CsInfo.KeyExchange == names.KX_ECDH {
		if certo.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return false
		}
	}

	switch key.Curve {
	case elliptic.P224():
		curveId = names.SECP224R1

	case elliptic.P256():
		curveId = names.SECP256R1

	case elliptic.P384():
		curveId = names.SECP384R1

	case elliptic.P521():
		curveId = names.SECP521R1

	default:
		return false
	}

	for _, sg := range sgs {
		if sg == curveId {
			return true
		}
	}

	return false
}

func getHSCertSign(opts *CertOpts, cert *x509.Certificate) bool {

	if opts == nil || cert == nil {
		return false
	}

	// For RSA KX theres no signature in the handshake and for
	// non RSA KX theres always digital signature
	if opts.CsInfo.KeyExchange != names.KX_RSA &&
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}

	switch opts.CsInfo.Auth {
	case names.SIG_RSA:
		if cert.PublicKeyAlgorithm != x509.RSA {
			return false
		}
	case names.SIG_DSS:
		if cert.PublicKeyAlgorithm != x509.DSA {
			return false
		}
	case names.SIG_ECDSA:
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			return false
		}
	default:
		return false
	}

	return true
}
