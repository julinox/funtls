package keyexchange

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

/*
	struct {
		HashAlgorithm hash;
		SignatureAlgorithm signature;
	} SignatureAndHashAlgorithm;
*/

//const _SignatureHeadSz = 4

var SignAlgoRSASupport = map[uint16]bool{
	names.RSA_PKCS1_SHA256:    true,
	names.RSA_PKCS1_SHA384:    true,
	names.RSA_PKCS1_SHA512:    true,
	names.RSA_PSS_RSAE_SHA256: true,
	names.RSA_PSS_RSAE_SHA384: true,
	names.RSA_PSS_RSAE_SHA512: true,
	names.SHA224_RSA:          true,
}

var SignAlgoECDSASupport = map[uint16]bool{
	names.ECDSA_SECP256R1_SHA256: true,
	names.ECDSA_SECP384R1_SHA384: true,
	names.ECDSA_SECP521R1_SHA512: true,
}

var SignAlgoDSASupport = map[uint16]bool{
	names.SHA224_DSA: true,
	names.SHA384_DSA: true,
	names.SHA512_DSA: true,
}

var tlsHashToCryptoHash = map[uint8]crypto.Hash{
	0x01: crypto.MD5,
	0x02: crypto.SHA1,
	0x03: crypto.SHA224,
	0x04: crypto.SHA256,
	0x05: crypto.SHA384,
	0x06: crypto.SHA512,
}

// Generates 'ecparams' signature and returns a buffer containing the
// required TLS format:
// HashAlgo (1B) | SignAlgo (1B) | SignatureLen (2B) | Signature
//
// Signature: ECDSA/RSA(Hash(CliRandom ||SrvRandom ||EcParams))
func SignServerKXParams(ecparams []byte, data *KXData) ([]byte, error) {

	if data == nil {
		return nil, fmt.Errorf("nil kxdata")
	}

	if len(ecparams) == 0 {
		return nil, fmt.Errorf("no bufferdata to sign")
	}

	sighScheme := getSignScheme(data.PrivateKey, data.SA)
	if sighScheme == 0 {
		return nil, fmt.Errorf("unmatched SA list for signing")
	}

	signer, ok := data.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("privatekey doesnt implement signer")
	}

	tlsHashID := uint8(sighScheme >> 8)
	hashFN, ok := tlsHashToCryptoHash[tlsHashID]
	if !ok {
		return nil, fmt.Errorf("tls-hash %d not supported", tlsHashID)
	}

	h := hashFN.New()
	h.Write(data.CliRandom)
	h.Write(data.SrvRandom)
	h.Write(ecparams)
	message := h.Sum(nil)
	/*totalLen := len(data.CliRandom) + len(data.SrvRandom) + len(ecparams)
	buffData := make([]byte, 0, totalLen)
	buffData = append(buffData, data.CliRandom...)
	buffData = append(buffData, data.SrvRandom...)
	buffData = append(buffData, ecparams...)
	message, err := hashMessage(buffData, hashFN)
	if err != nil {
		return nil, err
	}*/

	sign, err := signer.Sign(rand.Reader, message, hashFN)
	if err != nil {
		return nil, fmt.Errorf("crypto-signer error: %w", err)
	}

	// SignatureAndHashAlgorithm = 2 bytes, SignatureLen = 2 bytes
	totalLen := len(sign) + 4
	finalBuff := make([]byte, totalLen)
	binary.BigEndian.PutUint16(finalBuff, sighScheme)
	binary.BigEndian.PutUint16(finalBuff[2:], uint16(len(sign)))
	copy(finalBuff[4:], sign)
	//fmt.Printf("SignatureScheme: %v\n", names.SignHashAlgorithms[sighScheme])
	return finalBuff, nil
}

// Selects the appropriate SignatureScheme (2 bytes) by matching
// the server's private key type with the client's supported algorithms (SA).
// The high byte represents the Hash Algorithm and the low byte represents
// the Signature Algorithm.
func getSignScheme(pKey crypto.PrivateKey, saList []uint16) uint16 {

	var saSubset map[uint16]bool

	switch pKey.(type) {
	case *rsa.PrivateKey:
		saSubset = SignAlgoRSASupport

	case *ecdsa.PrivateKey:
		saSubset = SignAlgoECDSASupport

	case *dsa.PrivateKey:
		saSubset = SignAlgoDSASupport
	}

	for _, sa := range saList {
		if saSubset[sa] {
			return sa
		}
	}

	return 0
}

func hashMessage(data []byte, algo crypto.Hash) ([]byte, error) {

	switch algo {
	case crypto.SHA224:
		h := sha256.Sum224(data)
		return h[:], nil

	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:], nil

	case crypto.SHA384:
		h := sha512.Sum384(data)
		return h[:], nil

	case crypto.SHA512:
		h := sha512.Sum512(data)
		return h[:], nil

	default:
		return nil, fmt.Errorf("unsupported hash function")
	}
}
