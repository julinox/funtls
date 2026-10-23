package keyexchange

import (
	"crypto"

	"github.com/julinox/funtls/tlssl/names"
)

var SignAlgoRSASupport = map[uint16]bool{
	names.RSA_PKCS1_SHA256:    true,
	names.RSA_PKCS1_SHA384:    true,
	names.RSA_PKCS1_SHA512:    true,
	names.RSA_PSS_RSAE_SHA256: true,
	names.RSA_PSS_RSAE_SHA384: true,
	names.RSA_PSS_RSAE_SHA512: true,
	names.SHA224_RSA:          false,
}

var SignAlgoECDSASupport = map[uint16]bool{
	names.ECDSA_SECP256R1_SHA256: true,
	names.ECDSA_SECP384R1_SHA384: true,
	names.ECDSA_SECP521R1_SHA512: true,
}

var SignAlgoED25519Support = map[uint16]bool{
	names.ED25519: true,
}

var SignAlgoDSASupport = map[uint16]bool{
	names.SHA224_DSA: false,
	names.SHA384_DSA: false,
	names.SHA512_DSA: false,
}

func HashFN(sa uint16) crypto.Hash {

	switch sa {
	case names.ECDSA_SECP256R1_SHA256,
		names.RSA_PSS_PSS_SHA256,
		names.RSA_PSS_RSAE_SHA256,
		names.RSA_PKCS1_SHA256,
		names.SHA256_DSA:
		return crypto.SHA256

	case names.ECDSA_SECP384R1_SHA384,
		names.RSA_PSS_PSS_SHA384,
		names.RSA_PSS_RSAE_SHA384,
		names.RSA_PKCS1_SHA384,
		names.SHA384_DSA:
		return crypto.SHA384

	case names.ECDSA_SECP521R1_SHA512,
		names.RSA_PSS_PSS_SHA512,
		names.RSA_PSS_RSAE_SHA512,
		names.RSA_PKCS1_SHA512,
		names.SHA512_DSA:
		return crypto.SHA512

	case names.ED25519,
		names.ED448:
		return crypto.Hash(0)
	}

	return 0
}
