package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"tlesio/tlssl"
	ex "tlesio/tlssl/extensions"
)

type xServerHello struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewServerHello(actx *AllContexts) ServerHello {

	var newX xServerHello

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xServerHello) Name() string {
	return "_ServerHello_"
}

func (x *xServerHello) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerHello) Handle() error {

	var serverHelloBuf []byte

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	msgHello := x.ctx.GetMsgHello()
	if msgHello == nil {
		return fmt.Errorf("nil MsgHello object")
	}

	serverHelloBuf = make([]byte, 0)
	// Version
	serverHelloBuf = append(serverHelloBuf, x.setVersion()...)

	// Random
	random, err := x.random()
	if err != nil {
		return fmt.Errorf("error generating server random: %v", err)
	}

	serverHelloBuf = append(serverHelloBuf, random[:]...)

	// Session ID
	serverHelloBuf = append(serverHelloBuf, x.sessionID(msgHello)...)

	// Cipher Suite
	serverHelloBuf = append(serverHelloBuf, x.cipherSuites(msgHello)...)

	// "Compression methods"
	serverHelloBuf = append(serverHelloBuf, 0x00)

	// Extensions
	serverHelloBuf = append(serverHelloBuf, x.extensions(msgHello)...)

	// Headers
	header := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeServerHello,
		len(serverHelloBuf))

	// Set server hello buffer and client and server random (which are
	// needed for the session keys generation)
	x.ctx.SetBuffer(SERVERHELLO, append(header, serverHelloBuf...))
	x.ctx.SetBuffer(SERVERRANDOM, random)
	x.ctx.AppendOrder(SERVERHELLO)
	x.nextState = CERTIFICATE
	return nil
}

func (x *xServerHello) setVersion() []byte {

	// Force TLS 1.2
	return []byte{0x03, 0x03}
}

func (x *xServerHello) random() ([]byte, error) {

	newBuff := make([]byte, 32)
	_, err := rand.Read(newBuff)
	if err != nil {
		return nil, err
	}

	return newBuff, nil
}

func (x *xServerHello) sessionID(cliMsg *MsgHello) []byte {

	var newBuff []byte

	newBuff = append(newBuff, byte(len(cliMsg.SessionId)))
	newBuff = append(newBuff, cliMsg.SessionId...)
	return newBuff
}

func (x *xServerHello) cipherSuites(cliMsg *MsgHello) []byte {

	var cs uint16
	var newBuff []byte

	for _, algo := range cliMsg.CipherSuites {
		if x.tCtx.Modz.TLSSuite.IsSupported(algo) {
			newBuff = append(newBuff, byte(algo>>8), byte(algo))
			cs = algo
			break
		}
	}

	x.ctx.SetCipherSuite(cs)
	return newBuff
}

func (x *xServerHello) extensions(cliMsg *MsgHello) []byte {

	var extsBuffer []byte

	extsBuffer = make([]byte, 2)
	for extID, extData := range cliMsg.Extensions {
		ext := x.tCtx.Exts.Get(extID)
		// Renegiation info skip
		if ext.ID() == 0xFF01 {
			continue
		}

		// This should never happen
		if ext == nil || extData == nil {
			x.tCtx.Lg.Warnf("Packet Extension(%v) not found",
				ex.ExtensionName[extID])
			continue
		}

		auxBuffer, err := ext.PacketServerHelo(extData)
		if err != nil {
			x.tCtx.Lg.Errorf("Packet Extension(%v) : %v",
				ex.ExtensionName[extID], err)
			continue
		}

		if len(auxBuffer) == 0 {
			continue
		}

		extsBuffer = append(extsBuffer, auxBuffer...)
	}

	// Force renegotiation info
	rInfoBuff, err := x.tCtx.Exts.Get(0xFF01).PacketServerHelo(nil)
	if err != nil {
		x.tCtx.Lg.Errorf("Force Renegiation Info: %v", err)
	}

	extsBuffer = append(extsBuffer, rInfoBuff...)
	binary.BigEndian.PutUint16(extsBuffer, uint16(len(extsBuffer)-2))
	return extsBuffer
}
