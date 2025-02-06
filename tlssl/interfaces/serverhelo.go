package interfaces

import (
	"crypto/rand"
	"fmt"
	"tlesio/systema"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type ServerHello interface {
	Name() string
	Packet(*MsgHelloServer) []byte
	Handle(*MsgHelloCli) (*MsgHelloServer, error)
}

type MsgHelloServer struct {
	Version      [2]byte
	Random       [32]byte
	SessionId    []byte
	CipherSuites uint16
}

type xServerHello struct {
	mods *mx.ModuloZ
	exts *ex.Extensions
	lg   *logrus.Logger
}

func NewIfcServerHello(params *IfaceParams) ServerHello {

	if params == nil || params.Lg == nil ||
		params.Mx == nil || params.Ex == nil {
		return nil
	}

	return &xServerHello{
		lg:   params.Lg,
		mods: params.Mx,
		exts: params.Ex,
	}
}

func (sh *xServerHello) Name() string {
	return "ServerHello"
}

func (sh *xServerHello) Handle(msg *MsgHelloCli) (*MsgHelloServer, error) {

	var err error
	var newMsg MsgHelloServer

	if msg == nil {
		return nil, systema.ErrNilParams
	}

	err = newMsg.setVersion()
	if err != nil {
		return nil, err
	}

	err = newMsg.setRandom()
	if err != nil {
		return nil, err
	}

	err = newMsg.setCS(msg.CipherSuites, sh.mods.CipherSuites)
	if err != nil {
		return nil, err
	}

	return &newMsg, nil
}

// Build byte buffer from msg
func (sh *xServerHello) Packet(msg *MsgHelloServer) []byte {

	var newBuffer []byte

	if msg == nil {
		return nil
	}

	newBuffer = append(newBuffer, msg.Version[:]...)
	newBuffer = append(newBuffer, msg.Random[:]...)
	newBuffer = append(newBuffer, byte(len(msg.SessionId)))
	newBuffer = append(newBuffer, msg.SessionId...)
	newBuffer = append(newBuffer, byte(msg.CipherSuites>>8),
		byte(msg.CipherSuites))
	// "Compression methods"
	newBuffer = append(newBuffer, 0x00)
	return newBuffer
}

func (mh *MsgHelloServer) setVersion() error {

	// Force TLS 1.2
	mh.Version = [2]byte{0x03, 0x03}
	return nil
}

func (mh *MsgHelloServer) setRandom() error {

	random, err := generateServerRandom()
	if err != nil {
		return err
	}

	mh.Random = random
	return nil
}

func (mh *MsgHelloServer) setCS(algos []uint16, mod mx.ModCipherSuites) error {

	//cs, ok := modd.Execute(algos).(uint16)

	cs := mod.ChooseCS(algos)
	if cs == 0 {
		return fmt.Errorf("server hello error getting cipher suite")
	}

	mh.CipherSuites = cs
	return nil
}

func generateServerRandom() ([32]byte, error) {

	var random [32]byte

	_, err := rand.Read(random[:])
	if err != nil {
		return [32]byte{}, err
	}

	return random, nil
}
