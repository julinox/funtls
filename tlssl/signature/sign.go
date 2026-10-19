package signature

/*
In TLS 1.2 a signature_algorithms value only fixes the hash and the
signature algorithm; it does NOT fix the curve. The curve is the one
of the ECDSA key in the server certificate, and it MUST be a curve the
client offered in supported_groups (if that extension was sent).

Example "0x403": Means you need to use ECDSA + sha256, and you are not
foced to use a 256 bit curve (i.e secp256r1). However, if the client sends
SG list, the curve you chose must respect the list

ECDSA en TLS 1.2 (RFC 4492/8422)
- ecdsa_sha224 — 0x0303
- ecdsa_sha256 — 0x0403
- ecdsa_sha384 — 0x0503
- ecdsa_sha512 — 0x0603

ECDSA en TLS 1.3 (RFC 8446)
- ecdsa_secp256r1_sha256 — 0x0403
- ecdsa_secp384r1_sha384 — 0x0503
- ecdsa_secp521r1_sha512 — 0x0603
- ecdsa_brainpoolP256r1tls13_sha256 — 0x081A
- ecdsa_brainpoolP384r1tls13_sha384 — 0x081B
- ecdsa_brainpoolP512r1tls13_sha512 — 0x081C

RSA signature schemes in TLS. Naming pattern:
* rsa_<padding>_<keytype>_<hash>

	literal              padding  keytype  note
	rsa_pkcs1_sha256     pkcs1    classic  keytype omitted (rsaEncryption)
	rsa_pss_rsae_sha256  pss      rsae     key OID rsaEncryption
	rsa_pss_pss_sha256   pss      pss      key OID id-RSASSA-PSS

PSS parameters (hash, mgf1, salt_len, trailer):
classic key: derived from the scheme hash
hash_fn = hash, mgf1 = hash, salt_len = len(hash), trailer = 0xbc
pss key: provided by the key (RSASSA-PSS-params), must match scheme
*/

import (
	"crypto"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

type Fn1 func(int) int

var signSchemas = map[uint16]bool{
	names.RSA_PKCS1_SHA256: true,
	names.RSA_PKCS1_SHA384: true,
	/*names.RSA_PKCS1_SHA512:       true,
	names.RSA_PSS_RSAE_SHA256:    true,
	names.RSA_PSS_RSAE_SHA384:    true,
	names.RSA_PSS_RSAE_SHA512:    true,
	names.SHA224_DSA:             true,
	names.SHA384_DSA:             true,
	names.SHA512_DSA:             true,
	names.ECDSA_SECP256R1_SHA256: true,
	names.ECDSA_SECP384R1_SHA384: true,
	names.ECDSA_SECP521R1_SHA512: true,*/
}

type Signature interface {
	SignMe(uint16) error
}

type xSign struct {
	privKey crypto.PrivateKey
}

func NewSignature(pkey crypto.PrivateKey) (Signature, error) {

	var newSign xSign

	if pkey == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	newSign.privKey = pkey
	return &newSign, nil
}

// Assume little-endian
func (x *xSign) SignMe(schema uint16) error {

	// a = algorithm (ah[0]), h = hash (ah[1])
	var ah []byte

	if signSchemas[schema] {
		return fmt.Errorf("unssuported signature schema '%v'",
			names.SignatureAlgorithms[schema])
	}

	ah = make([]byte, 2)
	ah[0] = byte(schema)
	ah[1] = byte(schema >> 8)
	//fmt.Printf("ah[0]=%x | ah[1]=%x\n", ah[0], ah[1])

	return nil
}

func signRSA(pkey []byte, hh crypto.Hash) {

}

func gs1(i int) int {
	return 0
}

var pp = map[uint16]Fn1{
	names.RSA_PKCS1_SHA256: gs1,
}

/*
C = M^publica(e) mod n -> M = C^privada(d) mod n
F = H^privada(d) mod n ->
*/
