package names

const (
	KX_RSA = iota + 1
	KX_DHE
	KX_DH
	KX_ECDHE
	KX_ECDH
)

const (
	SIG_RSA = iota + 10
	SIG_DSS
	SIG_ECDSA
)

const (
	CIPHER_AES = iota + 20
	CIPHER_CHACHA20
	CIPHER_3DES
	CIPHER_RC4
)

const (
	MAC_HMAC = iota + 30
	MAC_AEAD
)

const (
	HASH_SHA1 = iota + 40
	HASH_SHA256
	HASH_SHA384
	HASH_SHA512
	HASH_MD5
)

const (
	CIPHER_STREAM = iota + 50
	CIPHER_CBC
	CIPHER_AEAD
)

// Types of cert keys
const (
	CERT_KEY_RSA = iota + 60
	CERT_KEY_ECDSA_P256
	CERT_KEY_ECDSA_P384
	CERT_KEY_ECDSA_P521
)

const (
	ECDSA_SECP256R1_SHA256 = 0x0403
	ECDSA_SECP384R1_SHA384 = 0x0503
	ECDSA_SECP521R1_SHA512 = 0x0603
	ED25519                = 0x0807
	ED448                  = 0x0808
	RSA_PSS_PSS_SHA256     = 0x0809
	RSA_PSS_PSS_SHA384     = 0x080A
	RSA_PSS_PSS_SHA512     = 0x080B
	RSA_PKCS1_SHA256       = 0x0401
	RSA_PKCS1_SHA384       = 0x0501
	RSA_PKCS1_SHA512       = 0x0601
	RSA_PSS_RSAE_SHA256    = 0x0804
	RSA_PSS_RSAE_SHA384    = 0x0805
	RSA_PSS_RSAE_SHA512    = 0x0806
	SHA224_ECDSA           = 0x0303
	SHA224_RSA             = 0x0301
	SHA224_DSA             = 0x0302
	SHA256_DSA             = 0x402
	SHA384_DSA             = 0x0502
	SHA512_DSA             = 0x0602
)

const (
	// RFC 7919 - Finite Field Diffie-Hellman Ephemeral
	FFDHE2048 = 0x0100
	FFDHE3072 = 0x0101
	FFDHE4096 = 0x0102
	FFDHE6144 = 0x0103
	FFDHE8192 = 0x0104

	// RFC 7748 - Montgomery Curves
	X25519 = 0x001D
	X448   = 0x001E

	// RFC 4492 (TLS ECC) - Named Curves (NIST P-curves)
	SECP256R1 = 0x0017
	SECP384R1 = 0x0018
	SECP521R1 = 0x0019
)

var SupportedGroups = map[uint16]string{
	SECP256R1: "secp256r1",
	SECP384R1: "secp384r1",
	SECP521R1: "secp521r1",
	X25519:    "x25519",
	X448:      "x448",
	FFDHE2048: "ffdhe2048",
	FFDHE3072: "ffdhe3072",
	FFDHE4096: "ffdhe4096",
	FFDHE6144: "ffdhe6144",
	FFDHE8192: "ffdhe8192",
}

var SignHashAlgorithms = map[uint16]string{
	ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
	ECDSA_SECP384R1_SHA384: "ecdsa_secp384r1_sha384",
	ECDSA_SECP521R1_SHA512: "ecdsa_secp521r1_sha512",
	ED25519:                "ed25519",
	ED448:                  "ed448",
	RSA_PSS_PSS_SHA256:     "rsa_pss_pss_sha256",
	RSA_PSS_PSS_SHA384:     "rsa_pss_pss_sha384",
	RSA_PSS_PSS_SHA512:     "rsa_pss_pss_sha512",
	RSA_PSS_RSAE_SHA256:    "rsa_pss_rsae_sha256",
	RSA_PSS_RSAE_SHA384:    "rsa_pss_rsae_sha384",
	RSA_PSS_RSAE_SHA512:    "rsa_pss_rsae_sha512",
	RSA_PKCS1_SHA256:       "rsa_pkcs1_sha256",
	RSA_PKCS1_SHA384:       "rsa_pkcs1_sha384",
	RSA_PKCS1_SHA512:       "rsa_pkcs1_sha512",
	SHA224_ECDSA:           "sha224_ecdsa",
	SHA224_RSA:             "sha224_rsa",
	SHA224_DSA:             "sha224_dsa",
	SHA256_DSA:             "sha256_dsa",
	SHA384_DSA:             "sha384_dsa",
	SHA512_DSA:             "sha512_dsa",
}

var TLSAlerts = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	21:  "decryption_failed_RESERVED",
	22:  "record_overflow",
	30:  "decompression_failure",
	40:  "handshake_failure",
	41:  "no_certificate_RESERVED",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	60:  "export_restriction_RESERVED",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	90:  "user_canceled",
	100: "no_renegotiation",
	110: "unsupported_extension",
}

var TLSLevels = map[uint8]string{
	1: "Warning",
	2: "Fatal",
}
