package handshake

import (
	"crypto/rand"
	"fmt"
	"tlesio/systema"
	tx "tlesio/tlssl/modulos"

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
	lg       *logrus.Logger
	mods     tx.TLSModulo
	helloMsg *MsgHelloServer
}

func NewServerHello(lg *logrus.Logger, mods tx.TLSModulo) ServerHello {

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

	sh.helloMsg = &newMsg
	err = sh.setVersion(msg.Version)
	if err != nil {
		return nil, err
	}

	err = sh.setRandom()
	if err != nil {
		return nil, err
	}

	err = sh.setCipherSuites(msg.CipherSuites)
	if err != nil {
		return nil, err
	}

	return sh.helloMsg, nil
}

func (sh *xServerHello) Name() string {
	return "ServerHello"
}

func (sh *xServerHello) setVersion(version [2]byte) error {

	sh.helloMsg.Version = version
	return nil
}

func (sh *xServerHello) setRandom() error {

	random, err := generateServerRandom()
	if err != nil {
		return err
	}

	sh.helloMsg.Random = random
	return nil
}

func (sh *xServerHello) setCipherSuites(algos []uint16) error {

	csm := sh.mods.Get(0xffff)
	if csm == nil {
		return fmt.Errorf("server hello error getting cipher suite module")
	}

	cs, ok := csm.Execute(algos).(uint16)
	if !ok {
		return fmt.Errorf("server hello error getting cipher suite")
	}

	sh.helloMsg.CipherSuites = cs
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
