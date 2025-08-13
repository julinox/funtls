package dhe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

type DHEPms struct {
	P       *big.Int
	G       *big.Int
	Public  *big.Int
	Private *big.Int
}

func NewDHEPms(ps []uint16) (*DHEPms, error) {

	var err error
	var newPms DHEPms

	newPms.Private, err = computePrivateDH()
	if err != nil {
		return nil, fmt.Errorf("computePrivateDH: %v", err)
	}

	newPms.Public = computePublicDH(newPms.Private)
	if newPms.Public == nil {
		return nil, fmt.Errorf("computePublicDH returned nil")
	}

	for _, p := range ps {
		if pg, exists := supportedGroupList[p]; exists {
			newPms.P = pg.p
			newPms.G = pg.g
			return &newPms, nil
		}
	}

	return nil, fmt.Errorf("no supported group found for %v", ps)
}

func (x *DHEPms) Encode() ([]byte, error) {

	var buffer []byte

	if x.P == nil || x.G == nil || x.Private == nil || x.Public == nil {
		return nil, fmt.Errorf("nil DHE parameters")
	}

	buffer = append(buffer, numberEncode(x.P)...)
	buffer = append(buffer, numberEncode(x.G)...)
	buffer = append(buffer, numberEncode(x.Public)...)
	if len(buffer) == 0 {
		return nil, fmt.Errorf("encoded DHE parameters are empty")
	}

	return buffer, nil
}

// Generates a private key for Diffie-Hellman key exchange
// This function generates a random integer in the range [2, p-2]
// where p is the prime number used in the Diffie-Hellman key exchange.
func computePrivateDH() (*big.Int, error) {

	xs, err := rand.Int(rand.Reader, new(big.Int).Sub(ffdhe2048_p_number,
		big.NewInt(2)))
	if err != nil {
		return nil, fmt.Errorf("GeneratePrivateExp: %v", err)
	}

	xs.Add(xs, big.NewInt(2))
	return xs, nil
}

func computePublicDH(xs *big.Int) *big.Int {
	return new(big.Int).Exp(ffdhe2048_g_number, xs, ffdhe2048_p_number)
}

// encodes a big.Int number into a byte slice.
// The format is [2 bytes length] [number bytes].
// The length is the number of bytes in the number
func numberEncode(number *big.Int) []byte {

	var buffer []byte

	if number == nil {
		return nil
	}

	bytes := number.Bytes()
	if len(bytes) == 0 {
		return nil
	}

	buffer = make([]byte, 2+len(bytes))
	binary.BigEndian.PutUint16(buffer, uint16(len(bytes)))
	copy(buffer[2:], bytes)
	return buffer
}
