package keyexchange

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

/*
	struct {
		HashAlgorithm hash;
		SignatureAlgorithm signature;
	} SignatureAndHashAlgorithm;
*/

const _SignatureHeadSz = 4

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

/*type DigitallySignedParams struct {
	ServerParams []byte
	ClientRandom   []byte
	ServerRandom   []byte
	SignatureAlgos []uint16
	PrivateKey     crypto.PrivateKey
}*/

// Signature: ECDSA/RSA(client_random || server_random || CurveParams)
func SignServerKXParams(ecparams []byte, data *KXData) ([]byte, error) {

	var signatureAlgo uint16

	if params == nil || params.PrivateKey == nil {
		return nil, fmt.Errorf("nil params/privatekey")
	}

	saSubset := getSASubset(params.PrivateKey)
	if saSubset == nil {
		return nil, fmt.Errorf("signature algorithms list not supported")
	}

	fmt.Println("SA LIST", params.SignatureAlgos)
	for _, sa := range params.SignatureAlgos {
		if saSubset[sa] {
			signatureAlgo = sa
			break
		}
	}

	fmt.Println("Signature Algorithm:", names.SignHashAlgorithms[signatureAlgo])
	/*signer, ok := params.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("privatekey doesnt implement signer")
	}

	data := append(params.ClientRandom, params.ServerRandom...)
	data = append(data, params.ServerParams...)
	message, err := hashMessage(data, )
	if err != nil {
		return nil, err
	}

	return signer.Sign(rand.Reader, message, params.HashAlgorithm)*/
	return nil, nil
}

func getSASubset(pKey crypto.PrivateKey) map[uint16]bool {

	switch pKey.(type) {
	case *rsa.PrivateKey:
		return SignAlgoRSASupport

	case *ecdsa.PrivateKey:
		return SignAlgoECDSASupport

	case *dsa.PrivateKey:
		return SignAlgoDSASupport
	}

	return nil
}

/*
func SignatureBuffer(data *SignData) []byte {

	if data == nil {
		return []byte{}
	}

	newBuffer := make([]byte, _SignatureHeadSz+len(data.Signature))
	newBuffer[0] = data.HashAlgo
	newBuffer[1] = data.SignAlgo
	binary.BigEndian.PutUint16(newBuffer[2:], uint16(len(data.Signature)))
	return newBuffer
}
*/

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
