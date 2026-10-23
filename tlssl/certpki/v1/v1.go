package v1

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"maps"

	"github.com/julinox/funtls/systema"
	cert "github.com/julinox/funtls/tlssl/certpki"
	kee "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

type pkInfo struct {
	cname     string
	saSupport map[uint16]bool // Supported Algorithms
	san       map[string]bool // Subject Alternative Names
	key       crypto.PrivateKey
	cSigner   crypto.Signer
	chain     []*x509.Certificate // 0 is the leaf
}

type xCertPKI struct {
	lg   *logrus.Logger
	info map[[32]byte]*pkInfo
}

func NewCertPki(lg *logrus.Logger, cp []*cert.CertPath) (cert.CertPKI, error) {

	var cPki xCertPKI

	myself := systema.MyName()
	if lg == nil {
		return nil, fmt.Errorf("nil logger (%s)", myself)
	}

	if len(cp) <= 0 {
		return nil, fmt.Errorf("empty paths (%s)", myself)

	}

	cPki.info = make(map[[32]byte]*pkInfo)
	cPki.lg = lg
	for _, p := range cp {
		cert, err := cPki.Load(p)
		if err != nil {
			cPki.lg.Warnf("cert load (%v): %v", p.ChainPath, err)
			continue
		}

		cPki.lg.Infof("Loaded cert '%v' (%v)", cert.Subject.CommonName,
			cert.PublicKeyAlgorithm)
	}

	return &cPki, nil
}

func (x *xCertPKI) Print() string {

	var str string

	i := 0
	for fp, pki := range x.info {
		var sans []string

		for s := range maps.Keys(pki.san) {
			sans = append(sans, s)
		}

		fpAux := hexToPointString(fp[:8])
		pka := pki.chain[0].PublicKeyAlgorithm
		if i < len(x.info)-1 {
			str += fmt.Sprintf("%v: %s (%v) | %v | %s\n", fpAux, pki.cname,
				pka, sans, printSASupport(pki.saSupport, ","))
		} else {
			str += fmt.Sprintf("%v: %s (%v) | %v | %s", fpAux, pki.cname,
				pka, sans, printSASupport(pki.saSupport, ","))
		}

		i++
	}

	return str
}

func (x *xCertPKI) GetFingerPrints() [][]byte {

	var fps [][]byte

	for fp := range x.info {
		fps = append(fps, fp[:])
	}

	return fps
}

func (x *xCertPKI) GetAll() [][]*x509.Certificate {

	var lista [][]*x509.Certificate

	for _, pki := range x.info {
		lista = append(lista, pki.chain)
	}

	return lista
}

func (x *xCertPKI) Get(fingerprint []byte) []*x509.Certificate {

	if len(fingerprint) == 0 {
		return nil
	}

	info, ok := x.info[[32]byte(fingerprint)]
	if !ok {
		return []*x509.Certificate{}
	}

	return info.chain
}

func (x *xCertPKI) GetPrivateKey(fingerprint []byte) crypto.PrivateKey {

	if len(fingerprint) == 0 {
		return nil
	}

	info, ok := x.info[[32]byte(fingerprint)]
	if !ok {
		return nil
	}

	return info.key
}

func (x *xCertPKI) GetSigner(fingerprint []byte) crypto.Signer {

	if len(fingerprint) == 0 {
		return nil
	}

	info, ok := x.info[[32]byte(fingerprint)]
	if !ok {
		return nil
	}

	return info.cSigner
}

func (x *xCertPKI) GetSaSupport(fingerprint []byte) map[uint16]bool {

	if len(fingerprint) == 0 {
		return nil
	}

	info, ok := x.info[[32]byte(fingerprint)]
	if !ok {
		return nil
	}

	return info.saSupport
}

func (x *xCertPKI) FingerPrint(cert *x509.Certificate) []byte {

	fp := certFingerPrint(cert)
	return fp[:]
}

func (x *xCertPKI) Load(path *cert.CertPath) (*x509.Certificate, error) {

	var peca pkInfo
	var fingerPrint [32]byte

	chain, err := loadCertificateChain(path.ChainPath)
	if err != nil {
		return nil, err
	}

	fingerPrint = certFingerPrint(chain[0])
	if len(chain) <= 0 {
		return nil, fmt.Errorf("no cert chain generated")
	}

	_, ok := x.info[fingerPrint]
	if ok {
		return nil, fmt.Errorf("already exists '%v' (%v)",
			chain[0].Subject.CommonName, chain[0].PublicKeyAlgorithm)
	}

	key, err := loadPrivateKey(path.KeyPath)
	if err != nil {
		return nil, err
	}

	if !validateKeyPair(chain[0], key) {
		return nil, fmt.Errorf("certificate and private key mismatch")
	}

	if err = certPreFlight(chain); err != nil {
		return nil, fmt.Errorf("certificate pre-flight check failed: %w", err)
	}

	peca.san = make(map[string]bool)
	peca.cname = chain[0].Subject.CommonName
	peca.key = key
	peca.chain = chain
	if err = peca.setSignAlgoSupport(); err != nil {
		return nil, err
	}

	if csign, ok := key.(crypto.Signer); ok {
		peca.cSigner = csign
	}

	peca.san[peca.cname] = true
	for _, san := range chain[0].DNSNames {
		peca.san[san] = true
	}

	x.info[fingerPrint] = &peca
	return peca.chain[0], nil
}

// PKCS#1 v1.5 vs. RSA-PSS
//
// - PKCS#1 v1.5 (rsa_pkcs1_*): the "classic" RSA signature padding, widely used
//   in TLS 1.2 and earlier.
//
// - RSA-PSS (rsa_pss_*): a modern RSA signature scheme (Probabilistic
//   Signature Scheme). It adds randomized padding and is provably secure
//   under stronger assumptions. Mandatory in TLS 1.3, optional in TLS 1.2.
//
// A PSS certificate explicitly declares that the key must be used only for
// RSA-PSS signatures, and includes exact PSS parameters: hash algorithm,
// MGF1, hash, salt length, etc.
//
// In contrast, a "normal" RSA certificate does not include any parameters
// and does not specify any signature scheme — it can be used with either
// PKCS#1 v1.5 or PSS, and when PSS is used the choice of parameters is
// deferred to the protocol (e.g., TLS).

// Both certificates may contain structurally identical RSA keys (modulus + exponent).
// The difference lies purely in intent and constraints declared in the certificate.
// While applications are expected to enforce these usage rules, nothing cryptographically
// prevents extracting the key and using it for encryption or non-PSS signing.

// Public key type in the certificate defines what is possible:
//
// - If the certificate contains a normal RSA key (OID rsaEncryption):
//   - It can be used with PKCS#1 v1.5 (rsa_pkcs1_*).
//   - It can also be used with PSS (rsa_pss_rsae_*).
//
// - If the certificate contains an RSA-PSS key (OID rsassaPss):
//   - It can only be used with PSS (rsa_pss_pss_*).
//   - PKCS#1 v1.5 is not allowed.
func (p *pkInfo) setSignAlgoSupport() error {

	p.saSupport = make(map[uint16]bool)
	leaf := p.chain[0]
	if leaf == nil || leaf.PublicKey == nil {
		return fmt.Errorf("invalid certificate or public key")
	}

	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		if isRSAPSSPublicKey(leaf.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("RSA-PSS public key found (not supported)")
		}

		aux, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid RSA public key type")
		}

		if aux.Size() < 128 {
			return fmt.Errorf("RSA public key size less than 128 bytes")
		}

		p.saSupport = maps.Clone(kee.SignAlgoRSASupport)

	case x509.DSA:
		p.saSupport = maps.Clone(kee.SignAlgoDSASupport)

	case x509.ECDSA:
		if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			switch pub.Curve {
			case elliptic.P256():
				aux := kee.SignAlgoECDSASupport[names.ECDSA_SECP256R1_SHA256]
				p.saSupport[names.ECDSA_SECP256R1_SHA256] = aux
			case elliptic.P384():
				aux := kee.SignAlgoECDSASupport[names.ECDSA_SECP384R1_SHA384]
				p.saSupport[names.ECDSA_SECP384R1_SHA384] = aux
			case elliptic.P521():
				aux := kee.SignAlgoECDSASupport[names.ECDSA_SECP521R1_SHA512]
				p.saSupport[names.ECDSA_SECP521R1_SHA512] = aux
			}
		}

	case x509.Ed25519:
		p.saSupport[names.ED25519] = kee.SignAlgoED25519Support[names.ED25519]
	}

	return nil
}
