package handshake

type MsgHelloCli struct {
	Version      [2]byte
	Random       [32]byte
	SessionId    []byte
	CipherSuites []uint16
	Extensions   map[uint16]interface{} //ExtensionType -> ExtensionData
}

type xClientHello struct {
	nextState int
	nextError error
	//ctx       HandShakeContext
}

func NewClientHello() ClientHello {
	return &xClientHello{}
}

func (x *xClientHello) Name() string {
	return "_ClientHello_"
}

func (x *xClientHello) Next() (int, error) {
	return x.nextState, x.nextError
}

func (x *xClientHello) Handle(data []byte) error {
	return nil
}
