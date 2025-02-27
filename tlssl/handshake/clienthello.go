package handshake

import "fmt"

type MsgHelloCli struct {
	Version      [2]byte
	Random       [32]byte
	SessionId    []byte
	CipherSuites []uint16
	Extensions   map[uint16]interface{} //ExtensionType -> ExtensionData
}

type xClientHello struct {
	stateBasicInfo
}

func NewClientHello(ctx HandShakeContext) ClientHello {

	var newX xClientHello

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xClientHello) Name() string {
	return "_ClientHello_"
}

func (x *xClientHello) Next() (int, error) {

	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xClientHello) Handle(data []byte) error {

	fmt.Println("I AM: ", x.Name())
	x.nextState = SERVERHELLO
	return nil
}
