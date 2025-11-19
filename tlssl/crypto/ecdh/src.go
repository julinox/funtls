package ecdh

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/julinox/funtls/tlssl/names"
)

// CurveMe([]uint16, *x509.Certificate) (*ECDHResult, error)
// MarshalParams(*ECDHResult) []byte
// SignParams(*x509.Certificate, []byte, []byte, []byte) ([]byte, error)
// BuildSKE(*ECDHResult, []byte, uint8, uint8) []byte
// entonces 'GenerateKey' me retorna '*ecdh.PrivateKey', y

// 03 | curve_id | len | 04| X | Y | Firma
// Firma: client_random || server_random || (03 | curve_id | len | 04||X||Y)
type NamedGroup uint16

type Eliptica struct {
	Group uint16
	Priv  []byte
	X     *big.Int
	Y     *big.Int
	Curva elliptic.Curve
}

func Curveame(sg []uint16, cert *x509.Certificate) (*Eliptica, error) {

	var err error
	var elp Eliptica

	curveGroup, curve := selectCurva(sg)
	if curveGroup == names.NOGROUP || curve == nil {
		return nil, fmt.Errorf("no ec curve supported for given sg list")
	}

	elp.Curva = curve
	elp.Group = curveGroup
	elp.Priv, elp.X, elp.Y, err = elliptic.GenerateKey(curve, crand.Reader)
	if err != nil {
		return nil, err
	}

	return &elp, nil
}

func (e *Eliptica) Marshall() []byte {

	var buffer []byte

	buffer = append(buffer, 0x03)
	binary.BigEndian.PutUint16(buffer[:], e.Group)
	return buffer
}

func selectCurva(sg []uint16) (uint16, elliptic.Curve) {

	var curvas []NamedGroup

	for _, curva := range sg {
		g := NamedGroup(curva)
		if g.eliptica() != nil {
			curvas = append(curvas, g)
		}
	}

	if len(curvas) == 0 {
		return names.NOGROUP, nil
	}

	n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(curvas))))
	sel := curvas[int(n.Int64())]
	return uint16(sel), sel.eliptica()
}

func (g NamedGroup) eliptica() elliptic.Curve {

	switch g {
	case names.SECP256R1:
		return elliptic.P256()
	case names.SECP384R1:
		return elliptic.P384()
	case names.SECP521R1:
		return elliptic.P521()
	default:
		return nil
	}
}
