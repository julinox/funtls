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
	Packet(*MsgHelloServer) []byte
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

func (sh *xServerHello) Name() string {
	return "ServerHello"
}

func (sh *xServerHello) Handle(msg *MsgHelloCli) (*MsgHelloServer, error) {

	var err error
	var newMsg MsgHelloServer

	if msg == nil {
		return nil, systema.ErrNilParams
	}

	err = newMsg.setVersion(msg.Version)
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
	// Compression methods
	newBuffer = append(newBuffer, 0x00)
	return newBuffer
}

func (mh *MsgHelloServer) setVersion(version [2]byte) error {

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
