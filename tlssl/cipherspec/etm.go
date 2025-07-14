package cipherspec

import (
	"github.com/julinox/funtls/tlssl"
)

// This function is a placeholder for the MTE-specific encryption logic.
// It should implement the encryption logic for the MTE cipher spec.
func (x *xCS) encryptETM(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	return nil, nil
}

func (x *xCS) decryptETM(record []byte) ([]byte, error) {

	return nil, nil
}
