package server

import (
	"fmt"
	"net"
	"tlesio/systema"
	"tlesio/tlssl"
	"tlesio/tlssl/handshake"
)

type xHandle struct {
	handhsake *handshake.Handshake
}

func Handle(ctx *tlssl.TLSContext, conn net.Conn) (*xHandle, error) {

	var err error
	var newHandle xHandle

	if ctx == nil || conn == nil {
		return nil, systema.ErrNilParams
	}

	handshakeCtx := handshake.NewHandShakeContext(ctx.Lg, conn)
	if handshakeCtx == nil {
		ctx.Lg.Error("error creating Handshake Context")
		return nil, systema.ErrNilParams
	}

	newHandle.handhsake, err = handshake.NewHandshake(handshakeCtx)
	if err != nil {
		ctx.Lg.Error(err)
		return nil, err
	}

	// Save client hello message
	return &newHandle, nil
}

func (x *xHandle) LetsTalk(cliHello []byte) {

	x.handhsake.Contexto.SetBuffer(handshake.CLIENTHELLO, cliHello)
	fmt.Println(systema.PrettyPrintBytes((x.handhsake.Contexto.GetBuffer(handshake.CLIENTHELLO))))
}
