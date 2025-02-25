package server

import (
	"net"
	"tlesio/systema"
	"tlesio/tlssl/handshake"
)

type xHandle struct {
	handhsake *handshake.Handshake
}

func Handle(ctx *TLSContext, buff []byte, conn net.Conn) (*xHandle, error) {

	var err error
	var newHandle xHandle

	if ctx == nil || buff == nil || conn == nil {
		return nil, systema.ErrNilParams
	}

	if len(buff) <= 45 {
		ctx.Lg.Error("buffer is too small for a client hello")
		return nil, systema.ErrInvalidBufferSize
	}

	handshakeParams := &handshake.HandshakeParams{
		CliHelloMsg:          buff,
		Coms:                 conn,
		Mods:                 ctx.Modz,
		Lg:                   ctx.Lg,
		Exts:                 ctx.Exts,
		ClientAuthentication: ctx.OptClientAuth,
	}

	newHandle.handhsake, err = handshake.NewHandshake(handshakeParams)
	if err != nil {
		ctx.Lg.Error(err)
		return nil, err
	}

	return &newHandle, nil
}

func (x *xHandle) LetsTalk() {
}
