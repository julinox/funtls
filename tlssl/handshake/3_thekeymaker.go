package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"math"
	"tlesio/tlssl/suite"

	"golang.org/x/crypto/sha3"
)

const (
	_SHA256_LEN_BYTES = 32
	_SHA384_LEN_BYTES = 48
)

type Keys struct {
	MAC []byte
	Key []byte
	IV  []byte
}

type SessionKeys struct {
	ClientKeys Keys
	ServerKeys Keys
}

type TheKeyMaker interface {
	PRF([]byte, []byte) []byte
}

type xKeyMake struct {
	hashAlgo int
	blockLen int
}

type shaCfg struct {
	shaLen int
	fn     func() hash.Hash
}

// All lens in bytes
func NewKeymaker(hashingAlgorithm, blockLen int) (TheKeyMaker, error) {

	var km xKeyMake

	switch hashingAlgorithm {
	case suite.SHA256:
		km.hashAlgo = suite.SHA256
		if blockLen < _SHA256_LEN_BYTES {
			return nil, fmt.Errorf("block len too short for SHA256")
		}

	case suite.SHA384:
		km.hashAlgo = suite.SHA384
		if blockLen < _SHA384_LEN_BYTES {
			return nil, fmt.Errorf("block len too short for SHA384")
		}

	default:
		return nil, fmt.Errorf("unsupported hashing algorithm")
	}

	km.blockLen = blockLen
	return &km, nil
}

// A(0) = seed
// A(i) = HMAC_hash(secret, A(i-1))
// P_hash(secret, seed) = 	HMAC_hash(secret, A(1) + seed) +
// HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
func (x *xKeyMake) PRF(secret, seed []byte) []byte {

	if secret == nil || seed == nil {
		return nil
	}

	switch x.hashAlgo {
	case suite.SHA256:
		return x.shamir(secret, seed, &shaCfg{
			shaLen: _SHA256_LEN_BYTES,
			fn:     sha256.New,
		})

	case suite.SHA384:
		return x.shamir(secret, seed, &shaCfg{
			shaLen: _SHA384_LEN_BYTES,
			fn:     sha3.New384,
		})
	}

	return nil
}

func (x *xKeyMake) shamir(secret, seed []byte, cfg *shaCfg) []byte {

	var blockKey []byte

	if cfg == nil {
		return nil
	}

	hmacHash := hmac.New(cfg.fn, secret)
	hmacHash.Write(seed)
	ai := hmacHash.Sum(nil)
	rounds := int(math.Ceil(float64(x.blockLen) / float64(cfg.shaLen)))

	for i := 0; i < rounds; i++ {
		hmacHash.Reset()
		hmacHash.Write(ai)
		hmacHash.Write(seed)
		blockKey = append(blockKey, hmacHash.Sum(nil)...)
		hmacHash.Reset()
		hmacHash.Write(ai)
		ai = hmacHash.Sum(nil)
	}

	return blockKey[:x.blockLen]
}
