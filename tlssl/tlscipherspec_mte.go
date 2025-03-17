package tlssl

import (
	"fmt"
	"tlesio/tlssl/suite"
)

func (x *xTLSCipherSpec) cbc(data []byte) (*TLSCipherText, error) {

	// This must be the 'Finished' message
	switch x.cipherMode {
	case suite.ETM:
		return nil, fmt.Errorf("no ETM yet")

	case suite.MTE:
		return x.cbcMTE(data)
	}

	return nil, fmt.Errorf("no specific mode to cipher")
}

// AESCBC^-1(CiphertText) = Plaintext || HMAC
func (x *xTLSCipherSpec) cbcMTE(data []byte) (*TLSCipherText, error) {

	fmt.Println("MODIFICADO")
	return nil, nil
}
