package tlssl

import (
	"fmt"
	"tlesio/systema"
)

func (x *xTLSCSpec) encryptETM(tpt *TLSPlaintext) (*TLSCipherText, error) {
	return nil, fmt.Errorf("not implemented encryptRecordETM")
}

func (x *xTLSCSpec) decryptETM(tct *TLSCipherText) (*TLSPlaintext, error) {

	myself := systema.MyName()
	return nil, fmt.Errorf("not implemented yet(%v)", myself)
}
