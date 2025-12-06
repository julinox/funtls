package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/julinox/funtls/tlssl/names"
)

// CurveMe([]uint16, *x509.Certificate) (*ECDHResult, error)
// MarshalParams(*ECDHResult) []byte
// SignParams(*x509.Certificate, []byte, []byte, []byte) ([]byte, error)
// BuildSKE(*ECDHResult, []byte, uint8, uint8) []byte
type NamedGroup uint16

type Ecdhe struct {
	Group uint16
	Priv  []byte
	X     *big.Int
	Y     *big.Int
	Curva elliptic.Curve
}

type ecdhe struct {
	x     *big.Int
	y     *big.Int
	curva elliptic.Curve
}

type dhe struct {
}

type KeyExchange struct {
	Group  uint16
	priv   []byte
	xEcdhe *ecdhe
	xDhe   *dhe
}

func NewEcdhe(sg []uint16) (*Ecdhe, error) {

	var err error
	var elp Ecdhe

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

func Unmarshal(buffer []byte) (*Ecdhe, error) {

	var ec Ecdhe

	if len(buffer) <= 5 {
		return nil, fmt.Errorf("incorrect buffer len")
	}

	if buffer[0] != 0x03 {
		return nil, fmt.Errorf("no named curve byte")
	}

	curveID := binary.BigEndian.Uint16(buffer[1:])
	ec.Curva = NamedGroup(curveID).eliptica()
	if ec.Curva == nil {
		return nil, fmt.Errorf("unknow curve/group")
	}

	ec.Group = curveID
	lenn := int(buffer[3])
	if len(buffer[4:]) != lenn {
		return nil, fmt.Errorf("len doesnt match 1byte+x+y")
	}

	if buffer[4] != 0x04 {
		return nil, fmt.Errorf("no uncompressed point byte")
	}

	sz := int((lenn - 1) / 2)
	if len(buffer[5:]) != sz*2 {
		return nil, fmt.Errorf("x|y len mismatch")
	}

	coordLen := (ec.Curva.Params().BitSize + 7) / 8
	if lenn != 1+2*coordLen {
		return nil, fmt.Errorf("len mismatch for curve")
	}

	ec.X = new(big.Int).SetBytes(buffer[5 : 5+sz])
	ec.Y = new(big.Int).SetBytes(buffer[5+sz:])
	if !ec.Curva.IsOnCurve(ec.X, ec.Y) {
		return nil, fmt.Errorf("point not on curve")
	}

	return &ec, nil
}

func (e *Ecdhe) BuildSKE(cRand, sRand []byte) ([]byte, error) {

	var err error
	var ske []byte
	var toSign []byte

	params, err := e.Marshall()
	if err != nil {
		return nil, err
	}

	toSign = append(toSign, cRand...)
	toSign = append(toSign, sRand...)
	toSign = append(toSign, params...)
	signature, err := e.sign(toSign)
	if err != nil {
		return nil, err
	}

	ske = append(ske, params...)
	ske = append(ske, 0x00, 0x00)
	binary.BigEndian.PutUint16(ske[len(params):], uint16(len(signature)))
	ske = append(ske, signature...)
	return ske, nil
}

func (e *Ecdhe) sign(msg []byte) ([]byte, error) {

	var hash []byte

	d := new(big.Int).SetBytes(e.Priv)
	privateKey := &ecdsa.PrivateKey{
		D: d,
	}

	privateKey.PublicKey.Curve = e.Curva
	privateKey.PublicKey.X = e.X
	privateKey.PublicKey.Y = e.Y
	switch e.Group {
	case names.SECP256R1:
		h := sha256.Sum256(msg)
		hash = h[:]

	case names.SECP384R1:
		h := sha512.Sum384(msg)
		hash = h[:]

	case names.SECP521R1:
		h := sha512.Sum512(msg)
		hash = h[:]

	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	if len(hash) == 0 {
		return nil, fmt.Errorf("message hash has no len")
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil

}

// CurveParams: 03 | curve_id(2B) | len (in bytes) | 04 | X | Y
// 03 = named_curve, 04 = uncompressed point
// Signature: ECDSA(client_random || server_random || CurveParams)
// SKE: CurveParams || Signature
func (e *Ecdhe) Marshall() ([]byte, error) {

	var sz int
	var buffer []byte

	if e.Curva == nil || e.X == nil || e.Y == nil {
		return nil, fmt.Errorf("nil params for Eliptica struct")
	}

	sz = (e.Curva.Params().BitSize + 7) / 8
	pX := paddy(e.X.Bytes(), sz)
	pY := paddy(e.Y.Bytes(), sz)
	totalLen := 1 + len(pX) + len(pY)
	// making space for 'PutUint16'
	buffer = append(buffer, 0x03, 0x00, 0x00)
	binary.BigEndian.PutUint16(buffer[1:], e.Group)
	buffer = append(buffer, byte(totalLen))
	buffer = append(buffer, 0x04)
	buffer = append(buffer, pX...)
	buffer = append(buffer, pY...)
	return buffer, nil
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

func paddy(buffer []byte, padSz int) []byte {

	if len(buffer) >= padSz {
		return buffer
	}

	newBuff := make([]byte, padSz)
	copy(newBuff[padSz-len(buffer):], buffer)
	return newBuff
}
