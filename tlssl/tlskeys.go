package tlssl

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/julinox/funtls/tlssl/suite"
	"github.com/sirupsen/logrus"
)

const (
	_SHA1_LEN_BYTES   = 20
	_SHA256_LEN_BYTES = 32
	_SHA384_LEN_BYTES = 48
)

type Keys struct {
	Hkey []byte
	Key  []byte
	IV   []byte
}

type SessionKeys struct {
	ClientKeys Keys
	ServerKeys Keys
}

type TheKeyMaker interface {
	PRF([]byte, string, []byte) []byte
}

type xKeyMake struct {
	hashAlgo int
	blockLen int
}

type shaCfg struct {
	//shaLen int
	fn func() hash.Hash
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

	default:
		return nil, fmt.Errorf("unsupported hash algorithm (maybe in TLS 1.4)")
	}

	km.blockLen = blockLen
	return &km, nil
}

// PRF(secret, label, seed) = P_hash(secret, label || seed)
func (x *xKeyMake) PRF(secret []byte, label string, seed []byte) []byte {

	seed = append([]byte(label), seed...)
	return x.pHash(secret, seed)
}

// A(0) = seed
// A(i) = HMAC_hash(secret, A(i-1))
// P_hash(secret, seed) = 	HMAC_hash(secret, A(1) + seed) +
// HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
func (x *xKeyMake) pHash(secret, seed []byte) []byte {

	if secret == nil || seed == nil {
		return nil
	}

	switch x.hashAlgo {
	case suite.SHA256:
		return x.shamir(secret, seed, sha256.New)
	}

	return nil
}

func (x *xKeyMake) shamir(secret, seed []byte, fn func() hash.Hash) []byte {

	var blockKey []byte

	hmacHash := hmac.New(fn, secret)
	hmacHash.Write(seed)
	ai := hmacHash.Sum(nil)

	for len(blockKey) < x.blockLen {
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

func (k *Keys) PrintKeys() string {
	return fmt.Sprintf("MAC: %x\nKey: %x\nIV: %x", k.Hkey, k.Key, k.IV)
}

func (k *Keys) PrintKeysWithLog(lg *logrus.Logger, tag string) {

	if lg == nil {
		return
	}

	lg.Tracef("%s MAC-Key: %x", tag, k.Hkey)
	lg.Tracef("%s Cipher-Key: %x", tag, k.Key)
	lg.Tracef("%s IV-Key: %x", tag, k.IV)
}
