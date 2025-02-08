package interfaces

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"tlesio/systema"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type ServerHello interface {
	Name() string
	Packet(*MsgHelloServer) []byte
	PacketExtensions(*MsgHelloCli) []byte
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

	var packetBuffer []byte

	if msg == nil {
		return nil
	}

	packetBuffer = append(packetBuffer, msg.Version[:]...)
	packetBuffer = append(packetBuffer, msg.Random[:]...)
	packetBuffer = append(packetBuffer, byte(len(msg.SessionId)))
	packetBuffer = append(packetBuffer, msg.SessionId...)
	packetBuffer = append(packetBuffer, byte(msg.CipherSuites>>8),
		byte(msg.CipherSuites))

	// "Compression methods"
	packetBuffer = append(packetBuffer, 0x00)
	return packetBuffer
}

func (x *xServerHello) PacketExtensions(msg *MsgHelloCli) []byte {

	var extsBuffer []byte

	if msg == nil {
		return nil
	}

	extsBuffer = make([]byte, 2)
	for extID, extData := range msg.Extensions {
		// This should never happen
		ext := x.exts.Get(extID)
		if ext == nil || extData == nil {
			x.lg.Warnf("Packet Extension(%v) not found",
				ex.ExtensionName[extID])
			continue
		}

		auxBuffer, err := ext.PacketServerHelo(extData)
		if err != nil {
			x.lg.Errorf("Packet Extension(%v) : %v",
				ex.ExtensionName[extID], err)
			continue
		}

		if len(auxBuffer) == 0 {
			continue
		}

		extsBuffer = append(extsBuffer, auxBuffer...)
	}

	binary.BigEndian.PutUint16(extsBuffer, uint16(len(extsBuffer)-2))
	return extsBuffer
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
