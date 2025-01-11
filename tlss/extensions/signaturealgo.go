package extensions

import (
	"encoding/binary"
)

var extnsByID = map[uint16]string{
	0x0000: "server_name",
	0x0001: "max_fragment_length",
	0x0002: "client_certificate_url",
	0x0003: "trusted_ca_keys",
	0x0004: "truncated_hmac",
	0x0005: "status_request",
	0x0006: "user_mapping",
	0x0007: "client_authz",
	0x0008: "server_authz",
	0x0009: "cert_type",
	0x000A: "supported_groups",
	0x000B: "ec_point_formats",
	0x000C: "srp",
	0x000D: "signature_algorithms",
	0x000E: "use_srtp",
	0x000F: "heartbeat",
	0x0010: "application_layer_protocol_negotiation",
	0x0011: "status_request_v2",
	0x0012: "signed_certificate_timestamp",
	0x0013: "client_certificate_type",
	0x0014: "server_certificate_type",
	0x0015: "padding",
	0x0016: "encrypt_then_mac",
	0x0017: "extended_master_secret",
	0x0018: "token_binding",
	0x0019: "cached_info",
	0x0023: "session_ticket",
}

type SignatureAlgorithms struct {
	size       int
	id         uint16
	algorithms []uint16
}

// Read the signature algorithms extension and choose the one
func newExtensionSignatureAlgorithms(buffer []byte) *SignatureAlgorithms {

	var sa SignatureAlgorithms

	if buffer == nil {
		return nil
	}

	offset := 2
	sa.id = 0x000D
	sa.size = int(binary.BigEndian.Uint16(buffer)) / 2
	sa.algorithms = make([]uint16, sa.size)
	for i := 0; i < sa.size; i++ {
		sa.algorithms[i] = binary.BigEndian.Uint16(buffer[offset:])
		offset += 2
	}

	return &sa
}

func (sa *SignatureAlgorithms) ID() uint16 {
	return 0x000D
}

func (sa *SignatureAlgorithms) Name() string {
	return extnsByID[sa.id]
}
