package keyexchange

// RFC 5246 §7.4.3 — Server Key Exchange (DHE)
// RFC 7919   — Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS
//
// In DHE the server chooses ephemeral DH parameters (p, g) and sends
// its public value Ys = g^priv mod p. The client replies with its own
// public value Yc = g^priv_c mod p in the ClientKeyExchange message.
// Both sides then compute the PMS independently:
//   server: PMS = Yc ^ priv   mod p
//   client: PMS = Ys ^ priv_c mod p
//
// Unlike ECDHE, RFC 5246 places no constraint from the client on the
// choice of (p, g) — the server picks freely. RFC 7919 extends
// SupportedGroups to include named FFDHE groups (ffdhe2048..ffdhe8192)
// so that the client can signal preferred groups; the server SHOULD
// honor them if it supports any of the listed groups.
//
// Named FFDHE groups (RFC 7919 Appendix A):
//   ffdhe2048 (0x0100)
//   ffdhe3072 (0x0101)
//   ffdhe4096 (0x0102)
//   ffdhe6144 (0x0103)
//   ffdhe8192 (0x0104)
// All groups use g=2 and a well-known safe prime p.
//
// ServerDHParams (RFC 5246 §7.4.3):
//   struct {
//       opaque dh_p <1..2^16-1>;
//       opaque dh_g <1..2^16-1>;
//       opaque dh_Ys<1..2^16-1>;
//   } ServerDHParams;
//
// Each field is length-prefixed with 2 bytes (big-endian).
// The signature in ServerKeyExchange covers:
//   client_random || server_random || ServerDHParams
//
// ServerKeyExchange wire format (DHE_RSA):
//
//   [1B  HandshakeType = 0x0C]
//   [3B  length of the rest]
//   [2B  dh_p length][dh_p bytes]
//   [2B  dh_g length][dh_g bytes]
//   [2B  dh_Ys length][dh_Ys bytes]
//   [1B  hash algorithm]
//   [1B  signature algorithm]
//   [2B  signature length]
//   [signature bytes]
//
// Note: the Handshake header (type+length) is added by the caller,
// not by this package. This file only builds ServerDHParams + signature.
