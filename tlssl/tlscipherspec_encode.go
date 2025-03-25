package tlssl

import (
	"fmt"
	"tlesio/systema"
)

func (x *xTLSCSpec) encodeCBC(data []byte) ([]byte, error) {

	myself := systema.MyName()
	switch x.macMode {
	case MODE_ETM:
		return x.encodeCBCETM(data)
	case MODE_MTE:
		return x.encodeCBCMTE(data)
	default:
		return nil, fmt.Errorf("no cipher mode(%v)", myself)
	}
}

func (x *xTLSCSpec) encodeCBCMTE(data []byte) ([]byte, error) {

	var tpt TLSPlaintext

	myself := systema.MyName()
	mac, err := x.Macintosh(data)
	if err != nil {
		return nil, fmt.Errorf("MAC calculation(%v): %v", myself, err)
	}

	tpt.Header = &TLSHeader{ContentType: ContentTypeApplicationData}
	if x.seqNum == 0 {
		tpt.Header.ContentType = ContentTypeHandshake
	}

	fmt.Printf("MAC: %x\n", mac)
	tpt.Fragment = append(tpt.Fragment, data...)
	tpt.Fragment = append(tpt.Fragment, mac...)
	x.EncryptRecord(&tpt)
	return nil, fmt.Errorf("not implemented encodeCBCMTE")
}

func (x *xTLSCSpec) encodeCBCETM(data []byte) ([]byte, error) {

	return nil, fmt.Errorf("not implemented encodeCBCETM")
}
