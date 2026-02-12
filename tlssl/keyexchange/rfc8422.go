package keyexchange

// RFC 8422
// For ECC ciphers theres two extensions that must be taken in account:
// elliptic_curves(10),
// ec_point_formats(11)

// If client send these extension then it becomes a constraint
// for the server, meaning that the server must select a curve within the
// parameters provided by the client.
// In case the server cannot meet the client's requirements (expressed
// through these extensions) then the server must use a cipher suite that
// does not use ECC.

// * elliptic_curves (also known as 'supported groups')
//	enum {
//		deprecated(1..22),
//		secp256r1 (23), secp384r1 (24), secp521r1 (25),
//		x25519(29), x448(30),
//		reserved (0xFE00..0xFEFF),
//		deprecated(0xFF01..0xFF02),
//		(0xFFFF)
//}	NamedCurve;

// Order shows preference
//	struct {
//		NamedCurve named_curve_list<2..2^16-1>
//	} NamedCurveList;

// Support of 'uncompressed' format is mandatory
// If extension is not sent by client then server must asume
// that only 'uncompressed' format is supported

// If client sends this extension without 'uncompressed' and at the same
// time uses SupportedGroups extension with only ECC curves, the server
// must abort the handshake.

// enum {
// 		uncompressed (0),
// 		deprecated (1..2),
// 		reserved (248..255)
// } ECPointFormat;

// struct {
// 		ECPointFormat ec_point_format_list<1..2^8-1>
// } ECPointFormatList

// enum {
// 		deprecated (1..2),
// 		named_curve (3),
// 		reserved(248..255)
// } ECCurveType;

// struct {
//      // 1 byte length field followed by data.
//      // First byte of data is the 'ECPointFormat'
//      // as specified in ANSI X9.62 / SEC 1.
//      opaque point <1..2^8-1>;
// } ECPoint;

// struct {
// 		ECCurveType curve_type;
// 		select (curve_type) {
// 			case named_curve:
// 				NamedCurve namedcurve;
// 		};
// } ECParameters;

// struct {
// 		ECParameters curve_params;
// 		ECPoint public;
// } ServerECDHParams;

import (
	"crypto"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/julinox/funtls/tlssl/names"
)

const _DEFAULT_ECDHE_GROUP = names.SECP256R1
const _CurveTypeNamed = 0x03 // named curve

// Only 'named curve' is supported
type ecParameters struct {
	curveType    byte
	namedCurveID uint16
}

type ECKXCurve struct {
	Grupo   uint16
	Curva   ecdh.Curve
	Private *ecdh.PrivateKey
}

type ECKXConfig struct {
	Lowest bool
	Tax    uint16
	SG     []uint16
	SA     []uint16
}

type KXData struct {
	CliRandom  []byte
	SrvRandom  []byte
	SG         []uint16
	SA         []uint16
	PrivateKey crypto.PrivateKey
}

func ECXKInit(opts *ECKXConfig) (*ECKXCurve, error) {

	var err error
	var kx ECKXCurve

	if opts == nil {
		return nil, fmt.Errorf("nil params")
	}

	if opts.Tax != 0 && curvaSwitch(opts.Tax) != nil {
		kx.Grupo = opts.Tax
	} else {
		kx.Grupo = selectGrupo(opts.SG, opts.Lowest)
	}

	if kx.Grupo == names.NOGROUP {
		return nil, fmt.Errorf("no ec curve supported for given sg list")
	}

	kx.Curva = curvaSwitch(kx.Grupo)
	kx.Private, err = kx.Curva.GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}

	return &kx, nil
}

func ECKXServerParams(kxParams *ECKXCurve) []byte {

	var buffer []byte

	if kxParams == nil || kxParams.Private == nil {
		return []byte{}
	}

	// 'ECParameters' setting
	buffer = ecParametersbuffer(&ecParameters{
		curveType:    _CurveTypeNamed,
		namedCurveID: kxParams.Grupo,
	})

	// 'ECPoint' setting
	ecPoint := kxParams.Private.PublicKey().Bytes()
	buffer = append(buffer, uint8(len(ecPoint)))
	buffer = append(buffer, ecPoint...)
	return buffer
}

// | 0x03(1B) | curve_id(2B) |
func ecParametersbuffer(x *ecParameters) []byte {

	newBuffer := make([]byte, 3)
	newBuffer[0] = x.curveType
	binary.BigEndian.PutUint16(newBuffer[1:], x.namedCurveID)
	return newBuffer
}

// Selects a group from the given sg list. If lowest is true, selects
// the "lowest" (based on id) group. Otherwise selects a random group
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
