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
)

const (
	// RFC 7919 - Finite Field Diffie-Hellman Ephemeral
	FFDHE2048 = 0x0100
	FFDHE3072 = 0x0101
	FFDHE4096 = 0x0102
	FFDHE6144 = 0x0103
	FFDHE8192 = 0x0104

	// RFC 7748 - Elliptic Curves
	X25519 = 0x001D
	X448   = 0x001E

	// RFC 4492 / RFC 8422 - Named Curves
	SECP256R1 = 0x0017
	SECP384R1 = 0x0018
	SECP521R1 = 0x0019

	// RFC 3526 / RFC 7919 Appendix A - MODP Groups
	MODP2048 = 0x000E
	MODP3072 = 0x000F
	MODP4096 = 0x0010
	MODP6144 = 0x0011
	MODP8192 = 0x0012
)

var SupportedGroups = map[uint16]string{
	MODP2048:  "modp2048",
	MODP3072:  "modp3072",
	MODP4096:  "modp4096",
	MODP6144:  "modp6144",
	MODP8192:  "modp8192",
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
