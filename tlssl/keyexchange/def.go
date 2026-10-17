package keyexchange

import (
	"github.com/julinox/funtls/tlssl/names"
)

const _DEFAULT_DHE_GROUP = names.FFDHE2048
const _DEFAULT_ECDHE_GROUP = names.SECP256R1

type ffdhegroup struct {
	enable bool
	p      []byte
	q      []byte
	g      []byte
}

var ffdhegroups = map[uint16]ffdhegroup{
	names.FFDHE2048: {enable: true, g: FFDHE_G,
		p: FFDHE2048_P, q: FFDHE2048_Q},
	names.FFDHE3072: {enable: true, g: FFDHE_G,
		p: FFDHE3072_P, q: FFDHE3072_Q},
	names.FFDHE4096: {enable: true, g: FFDHE_G,
		p: FFDHE4096_P, q: FFDHE4096_Q},
	names.FFDHE6144: {enable: true, g: FFDHE_G,
		p: FFDHE6144_P, q: FFDHE6144_Q},
	names.FFDHE8192: {enable: false, g: FFDHE_G,
		p: FFDHE8192_P, q: FFDHE8192_Q},
}

type KeyExchange interface {
	Public() []byte
	Params() []byte
	GroupName() string
	SharedSecret([]byte) ([]byte, error)
}
