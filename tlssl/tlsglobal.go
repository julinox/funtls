package tlssl

import (
	ex "github.com/julinox/funtls/tlssl/extensions"
	mx "github.com/julinox/funtls/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

const VERIFYDATALEN = 12

const (
	MODE_MTE = iota + 1
	MODE_ETM
)

type TLSContext struct {
	Lg            *logrus.Logger
	Certs         mx.ModCerts
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
	OptClientAuth bool // Enable Client Authentication
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
