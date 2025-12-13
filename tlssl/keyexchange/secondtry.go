package keyexchange

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"crypto/ecdh"

	"github.com/julinox/funtls/tlssl/names"
)

type ServerKX struct {
	grupo   uint16
	curva   ecdh.Curve
	private *ecdh.PrivateKey
}

type ServerKXOpts struct {
	Lowest bool
	Tax    uint16
	SG     []uint16
}

func NewServerKX(opts *ServerKXOpts) (*ServerKX, error) {

	var err error
	var kx ServerKX

	if opts == nil {
		return nil, fmt.Errorf("nil params")
	}

	if opts.Tax != 0 && curvaSwitch(opts.Tax) != nil {
		kx.grupo = opts.Tax
	} else {
		kx.grupo = selectGrupo(opts.SG, opts.Lowest)
	}

	if kx.grupo == names.NOGROUP {
		return nil, fmt.Errorf("no ec curve supported for given sg list")
	}

	kx.curva = curvaSwitch(kx.grupo)
	kx.private, err = kx.curva.GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}

	return &kx, nil
}

// According to RFC 8422 this is the format for server ecdh params:
//
//	struct {
//	 ECParameters    curve_params;
//	 ECPoint         public;
//	} ServerECDHParams;
//
// curve_params: 0x03 | curve_id(2B)
// public: len (in bytes) | 0x04 | X | Y
func (kx *ServerKX) Params() []byte {

	var buffer []byte

	ecPoint := kx.private.PublicKey().Bytes()
	sz := 4 + len(ecPoint)
	buffer = make([]byte, sz)
	buffer[0] = 0x03
	binary.BigEndian.PutUint16(buffer[1:], kx.grupo)
	buffer[3] = uint8(len(ecPoint))
	copy(buffer[4:], ecPoint)
	return buffer
}

// Signature: ECDSA(client_random || server_random || CurveParams)
func (kx *ServerKX) Signature(msg []byte, key any) []byte {

	return nil
}

func selectGrupo(sg []uint16, lowest bool) uint16 {

	var grupo uint16
	var grupos []uint16

	if len(sg) == 0 {
		return _DEFAULT_ECDHE_GROUP
	}

	for _, group := range sg {
		if curvaSwitch(group) != nil {
			grupos = append(grupos, group)
		}
	}

	if len(grupos) == 0 {
		return names.NOGROUP
	}

	if lowest {
		grupo = grupos[0]
		for _, c := range grupos {
			if c < grupo {
				grupo = c
			}
		}

	} else {
		n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(grupos))))
		grupo = grupos[int(n.Int64())]
	}

	return grupo
}

func curvaSwitch(group uint16) ecdh.Curve {

	switch group {
	case names.SECP256R1:
		return ecdh.P256()
	case names.SECP384R1:
		return ecdh.P384()
	case names.SECP521R1:
		return ecdh.P521()
	default:
		return nil
	}
}
