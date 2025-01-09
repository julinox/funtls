package tlss

import (
	"encoding/binary"
	"fmt"
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
	Size       int
	Algorithms []uint16
}

func NewExtension(buffer []byte) interface{} {

	// buffer should point to the beginning of the extension

	if buffer == nil {
		return nil
	}

	id := binary.BigEndian.Uint16(buffer[:2])
	switch id {
	case 0x0030: // signature_algorithms
		return NewExtensionSignatureAlgorithms(buffer[2:])
	default:
		return nil
	}
}

func NewExtensionSignatureAlgorithms(buffer []byte) *SignatureAlgorithms {

	var sa SignatureAlgorithms

	if buffer == nil {
		return nil
	}

	fmt.Println("MIRA LA SIGNATURA DE ALGORITMOS")
	return &sa
}

func getExtensionIDByName(name string) (uint16, bool) {
	for id, extName := range extnsByID {
		if extName == name {
			return id, true
		}
	}
	return 0, false
}
