package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"
)

func (x *xCS) decryption(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	return nil, fmt.Errorf("unsupported CipherType: %v",
		x.cipherSuite.Info().CipherType)
}
