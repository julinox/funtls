package dhe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

type DHEPms struct {
	X *big.Int // private value
	Y *big.Int // public value
}

func NewDHEPms() (*DHEPms, error) {

	var err error
	var newPms DHEPms

	newPms.X, err = computePrivateDH()
	if err != nil {
		return nil, fmt.Errorf("computePrivateDH: %v", err)
	}

	newPms.Y = computePublicDH(newPms.X)
	if newPms.Y == nil {
		return nil, fmt.Errorf("computePublicDH returned nil")
	}

	return &newPms, nil
}

func EncodeDHE(pms *DHEPms) ([]byte, error) {

	var buffer []byte

	if pms == nil || pms.X == nil || pms.Y == nil {
		return nil, fmt.Errorf("nil DHE parameters")
	}

	buffer = append(buffer, numberEncode(ffdhe2048_p_number)...)
	buffer = append(buffer, numberEncode(ffdhe2048_g_number)...)
	buffer = append(buffer, numberEncode(pms.Y)...)
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
