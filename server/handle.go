package server

import (
	"net"
	"tlesio/systema"
	"tlesio/tlssl/handshake"
)

type xHandle struct {
	handhsake *handshake.Handshake
}

func HandleRequest(ssl *zzl, buff []byte, conn net.Conn) (*xHandle, error) {

	var err error
	var newHandle xHandle

	if ssl == nil || buff == nil || conn == nil {
		return nil, systema.ErrNilParams
	}

	if len(buff) <= 45 {
		ssl.lg.Error("buffer is too small for a client hello")
		return nil, systema.ErrInvalidBufferSize
	}

	handshakeParams := &handshake.HandshakeParams{
		CliHelloMsg:          buff,
		Coms:                 conn,
		Mods:                 ssl.modz,
		Lg:                   ssl.lg,
		Exts:                 ssl.exts,
		Ifaces:               ssl.ifs,
		ClientAuthentication: ssl.clientAuth,
	}

	newHandle.handhsake, err = handshake.NewHandshake(handshakeParams)
	if err != nil {
		ssl.lg.Error(err)
		return nil, err
	}

	return &newHandle, nil
}

func (x *xHandle) LetsTalk() {
}
