package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
)

// This function is a placeholder for the MTE-specific encryption logic.
// It should implement the encryption logic for the MTE cipher spec.
func (x *xCS) encryptMTE(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	var err error
	var cipherText []byte

	myself := systema.MyName()
	mac, err := x.macOS(ct, pt)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	fmt.Printf("MTECIO ENCRYPT: %x\n", mac)
	return cipherText, nil
}

func (x *xCS) decryptMTE(record []byte) ([]byte, error) {

	return nil, nil
}
