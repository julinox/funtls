package interfaces

import (
	"crypto/rand"
	"fmt"
	"tlesio/systema"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type ServerHello interface {
	Name() string
	Handle(*MsgHelloCli) (*MsgHelloServer, error)
}

type MsgHelloServer struct {
	Version      [2]byte
	Random       [32]byte
	SessionId    []byte
	CipherSuites uint16
}

type xServerHello struct {
	lg   *logrus.Logger
	mods mx.TLSModulo
}

func NewServerHello(lg *logrus.Logger, mods mx.TLSModulo) ServerHello {

	if lg == nil || mods == nil {
		return nil
	}

	return &xServerHello{
		lg:   lg,
		mods: mods,
	}
}

func (sh *xServerHello) Handle(msg *MsgHelloCli) (*MsgHelloServer, error) {

	var err error
	var newMsg MsgHelloServer

	if msg == nil {
		return nil, systema.ErrNilParams
	}

	err = newMsg.setVersion(newMsg.Version)
	if err != nil {
		return nil, err
	}

	err = newMsg.setRandom()
	if err != nil {
		return nil, err
	}

	// Get Cipher Suite module
	modd := sh.mods.Get(0xffff)
	if modd == nil {
		// This should never happen
		return nil, fmt.Errorf("server hello error getting cipher suite module")
	}

	err = newMsg.setCS(msg.CipherSuites, modd)
	if err != nil {
		return nil, err
	}

	return &newMsg, nil
}

func (sh *xServerHello) Name() string {
	return "ServerHello"
}

func (mh *MsgHelloServer) setVersion(version [2]byte) error {

	mh.Version = version
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

func (mh *MsgHelloServer) setCS(algos []uint16, modd mx.Modulo) error {

	cs, ok := modd.Execute(algos).(uint16)
	if !ok {
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
