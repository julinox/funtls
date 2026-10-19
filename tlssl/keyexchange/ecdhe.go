package keyexchange

/*
ECDHE:
Montgomery (RFC 7748)
- x25519 — 0x001D (29)
- x448 — 0x001E (30)

NIST P-curves (RFC 4492/8422)
- secp256r1 / prime256v1 / P-256 — 0x0017 (23)
- secp384r1 / P-384 — 0x0018 (24)
- secp521r1 / P-521 — 0x0019 (25)
- (deprecadas: secp192r1 0x0013, secp224r1 0x0015)

Koblitz
- secp256k1 — 0x0016 (22) (legacy; casi nunca en TLS)
*/
