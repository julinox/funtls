package tlssl

import (
	"fmt"
	"tlesio/systema"
)

func (x *xTLSCipherSpec) encodeCBC(data []byte) ([]byte, error) {

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

func (x *xTLSCipherSpec) encodeCBCMTE(data []byte) ([]byte, error) {

	// Give me the TLS header

	var tlsHeader TLSHeader

	myself := systema.MyName()
	// Set TLS header for Mac calculation
	if x.seqNum == 0 {
		if len(data) < 1 {
			return nil, fmt.Errorf("empty data on first packet(%v)", myself)
		}

		tlsHeader.ContentType = ContentTypeHandshake
	} else {
		tlsHeader.ContentType = ContentTypeApplicationData
	}

	tlsHeader.Version = TLS_VERSION1_2
	tlsHeader.Len = len(data)
	fmt.Printf("Header MAC calc: %v\n", &tlsHeader)
	//tlsHead := TLSHeadPacket(data)
	fmt.Println("Running encodeCBCMTE------------")
	return nil, fmt.Errorf("not implemented encodeCBCMTE")
}

func (x *xTLSCipherSpec) encodeCBCETM(data []byte) ([]byte, error) {

	return nil, fmt.Errorf("not implemented encodeCBCETM")
}
