package tlssl

import (
	pki "github.com/julinox/funtls/tlssl/certpki"
	ex "github.com/julinox/funtls/tlssl/extensions"
	mx "github.com/julinox/funtls/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

// TLS record limits according to RFC 5246:
//   - MaxPlaintextSize: 16384 bytes (2^14).
//   - MaxCiphertextOverhead: 1024 bytes (RFC 5246 limit, though no modern
//     cipher reaches this; AES-CBC with SHA-384 and max padding reaches ~320).
//   - MaxCompressionOverhead: 1024 bytes (Rarely used/deprecated).
//   - RecordHeaderSize: 5 bytes.
//
// Maximum practical buffer (no compression): 17413 bytes.
// Maximum theoretical buffer (with compression): 18437 bytes.
const MALLOCBUFF = 1024 * 17
const VERIFYDATALEN = 12

const (
	MODE_MTE = iota + 1
	MODE_ETM
)

type TLSContext struct {
	OptClientAuth bool
	CertPKI       pki.CertPKI
	Lg            *logrus.Logger
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
}
