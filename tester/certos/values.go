package certos

import (
	"crypto/aes"
	"crypto/sha256"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

var saAlgos1 = []uint16{
	names.ECDSA_SECP256R1_SHA256,
	names.ECDSA_SECP384R1_SHA384,
	names.ECDSA_SECP521R1_SHA512,
	names.RSA_PSS_PSS_SHA256,
	names.RSA_PKCS1_SHA512,
	names.SHA224_ECDSA,
}

var csEcdheEcdsa = &suite.SuiteInfo{
	Mac:         names.MAC_HMAC,
	CipherType:  names.CIPHER_CBC,
	Hash:        names.HASH_SHA256,
	HashSize:    sha256.Size,
	Cipher:      names.CIPHER_AES,
	KeySize:     32,
	KeySizeHMAC: 32,
	IVSize:      aes.BlockSize,
	KeyExchange: names.KX_ECDHE,
	Auth:        names.SIG_ECDSA,
}

var csDheEcdsa = &suite.SuiteInfo{
	Mac:         names.MAC_HMAC,
	CipherType:  names.CIPHER_CBC,
	Hash:        names.HASH_SHA256,
	HashSize:    sha256.Size,
	Cipher:      names.CIPHER_AES,
	KeySize:     32,
	KeySizeHMAC: 32,
	IVSize:      aes.BlockSize,
	KeyExchange: names.KX_DHE,
	Auth:        names.SIG_ECDSA,
}

var supportedGroups = []uint16{
	names.SECP256R1,
	names.SECP384R1,
	names.SECP521R1,
	names.FFDHE2048,
	names.FFDHE3072,
	names.X448,
	names.X25519,
}
