package keymaker

import (
	"fmt"
	"testing"

	"tlesio/tlssl/handshake"
	"tlesio/tlssl/suite"
)

func TestPRFSha2(t *testing.T) {

	// AES256-CBC | sha256 = 32, KeyLen = 32, IV = 16 bytes
	// SessionKeys = 2 * (32 + 32 + 16) = 160 bytes

	pf, err := handshake.NewKeymaker(suite.SHA256, 160)
	if err != nil {
		t.Error(err)
	}

	secret := []byte("secreto")
	seed := []byte("semilla")
	pp := pf.PRF(secret, seed)
	fmt.Printf("%x\nMaterial Len: %v\n", pp, len(pp))

}
func TestPRFSha3(t *testing.T) {

	// AES256-CBC | sha384 = 48, KeyLen = 32, IV = 16 bytes
	// SessionKeys = 2 * (48 + 32 + 16) = 192 bytes

	pf, err := handshake.NewKeymaker(suite.SHA384, 192)
	if err != nil {
		t.Error(err)
	}

	secret := []byte("secreto")
	seed := []byte("semilla")
	pp := pf.PRF(secret, seed)
	fmt.Printf("%x\nMaterial Len: %v\n", pp, len(pp))
}
