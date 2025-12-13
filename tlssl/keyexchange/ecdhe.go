package keyexchange

import (
	"crypto"
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

const _DEFAULT_ECDHE_GROUP = names.SECP256R1

type KXecdhe struct {
	Priv  []byte
	Group uint16
	X     *big.Int
	Y     *big.Int
	Curva elliptic.Curve
}

type signRS struct {
	r *big.Int
	s *big.Int
}

func KXEcdhe(sg []uint16, lowestCurve bool) (*KXecdhe, error) {

	var err error
	var kx KXecdhe

	kx.Curva, kx.Group = selectCurva(sg, lowestCurve)
	if kx.Group == names.NOGROUP {
		return nil, fmt.Errorf("no ec curve supported for given sg list")
	}

	priv, x, y, err := elliptic.GenerateKey(kx.Curva, crand.Reader)
	if err != nil {
		return nil, err
	}

	kx.X = x
	kx.Y = y
	kx.Priv = priv
	return &kx, nil
}

func KXEcdheUnmarshal(buffer []byte) (*KXecdhe, error) {

	var ec KXecdhe

	if len(buffer) <= 5 {
		return nil, fmt.Errorf("incorrect buffer len")
	}

	if buffer[0] != 0x03 {
		return nil, fmt.Errorf("no named curve byte")
	}

	curveID := binary.BigEndian.Uint16(buffer[1:])
	ec.Curva = eliptica2(curveID)
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

func (kx *KXecdhe) Marshall() ([]byte, error) {

	var sz int
	var buffer []byte

	if kx.Curva == nil || kx.X == nil || kx.Y == nil {
		return nil, fmt.Errorf("nil params for Eliptica struct")
	}

	sz = (kx.Curva.Params().BitSize + 7) / 8
	pX := paddy(kx.X.Bytes(), sz)
	pY := paddy(kx.Y.Bytes(), sz)
	totalLen := 1 + len(pX) + len(pY)
	// making space for 'PutUint16'
	buffer = append(buffer, 0x03, 0x00, 0x00)
	binary.BigEndian.PutUint16(buffer[1:], kx.Group)
	buffer = append(buffer, byte(totalLen))
	buffer = append(buffer, 0x04)
	buffer = append(buffer, pX...)
	buffer = append(buffer, pY...)
	return buffer, nil
}

// CurveParams: 0x03 | curve_id(2B) | len (in bytes) | 0x04 | X | Y
// 0x03 = named_curve, 0x04 = uncompressed point
// Signature: ECDSA(client_random || server_random || CurveParams)
// SKE: CurveParams || Signature
func (kx *KXecdhe) Ske(csRand []byte) ([]byte, error) {

	return nil, nil
}

// For ecdhe the hashing algorithm is implied by the curve used
// This is at least true for NIST curves
//
// Signatyre Format: HashAlgo | SignAlgo | len(signature) | signature
func PepitoFirma(msg []byte, key crypto.PrivateKey) {

	if key == nil {

	}
}

func (kx *KXecdhe) Signature(msg []byte) ([]byte, error) {

	var err error
	var hashAlgo byte
	var hashedMsg []byte

	d := new(big.Int).SetBytes(kx.Priv)
	privateKey := &ecdsa.PrivateKey{
		D: d,
	}

	privateKey.PublicKey.Curve = kx.Curva
	privateKey.PublicKey.X = kx.X
	privateKey.PublicKey.Y = kx.Y
	switch kx.Group {
	case names.SECP256R1:
		h := sha256.Sum256(msg)
		hashedMsg = h[:]
		hashAlgo = names.SHA256

	case names.SECP384R1:
		h := sha512.Sum384(msg)
		hashedMsg = h[:]
		hashAlgo = names.SHA384

	case names.SECP521R1:
		h := sha512.Sum512(msg)
		hashedMsg = h[:]
		hashAlgo = names.SHA512

	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	if len(hashedMsg) == 0 {
		return nil, fmt.Errorf("message hash has no len")
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedMsg)
	if err != nil {
		return nil, err
	}

	bitSz := (kx.Curva.Params().BitSize + 7) / 8
	return serializeSignature(r, s, hashAlgo, names.ECDSA, bitSz), nil
}

func selectCurva(sg []uint16, lowest bool) (elliptic.Curve, uint16) {

	var curva uint16
	var curvas []uint16

	if len(sg) == 0 {
		return eliptica2(_DEFAULT_ECDHE_GROUP), _DEFAULT_ECDHE_GROUP
	}

	for _, group := range sg {
		if eliptica2(group) != nil {
			curvas = append(curvas, group)
		}
	}

	if len(curvas) == 0 {
		return nil, names.NOGROUP
	}

	if lowest {
		curva = curvas[0]
		for _, c := range curvas {
			if c < curva {
				curva = c
			}
		}

	} else {
		n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(curvas))))
		curva = curvas[int(n.Int64())]
	}

	return eliptica2(curva), curva
}

// Format: HashAlgo (1B) | SignAlgo(1B) | lenSign(2B) | signature
func serializeSignature(r, s *big.Int, hAlg, sAlg byte, bitSz int) []byte {

	var buffer []byte

	if r == nil || s == nil {
		return nil
	}

	rN := r.FillBytes(make([]byte, bitSz))
	sN := s.FillBytes(make([]byte, bitSz))
	lenSign := len(rN) + len(sN)
	buffer = make([]byte, 4, 4+lenSign)
	buffer[0] = hAlg
	buffer[1] = sAlg
	binary.BigEndian.PutUint16(buffer[2:], uint16(lenSign))
	buffer = append(buffer, rN...)
	buffer = append(buffer, sN...)
	return buffer
}

func eliptica2(group uint16) elliptic.Curve {

	switch group {
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
