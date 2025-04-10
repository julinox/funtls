package server

import (
	"fmt"
	"net"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/handshake"

	evilmac "github.com/julinox/statemaquina"
	"github.com/sirupsen/logrus"
)

// All possible handhsake messages + all change cipher spec + all transitions.
// Transitions are not messages but are part of the handshake flow.
const _MAX_STATES_COUNT_ = 1 << 4

type xHandle struct {
	lg        *logrus.Logger
	handhsake *handshake.Handshake
}

func (x *xTLSListener) Accept() (net.Conn, error) {

	/*rawConn, err := x.Listener.Accept()
	if err != nil {
		x.tCtx.Lg.Error("error accepting connection: ", err)
		return nil, err
	}
	fmt.Println("ACEPTAR2")
	return nil, fmt.Errorf("not implemented")*/
	return nil, nil
}

func (x *xTLSListener) Close() error {
	return x.listener.Close()
}

func (x *xTLSListener) Addr() net.Addr {
	return x.listener.Addr()
}

// This file is the lowest level for logging stuff
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

	handshakeCtx.SetTransitionStage(handshake.STAGE_SERVERHELLODONE)
	newHandle.handhsake, err = handshake.NewHandshake(&handshake.AllContexts{
		Hctx: handshakeCtx,
		Tctx: ctx})

	if err != nil {
		ctx.Lg.Error(err)
		return nil, err
	}

	newHandle.lg = ctx.Lg
	return &newHandle, nil
}

func (x *xHandle) LetsTalk(cliHello []byte) {

	var err error

	b166er, err := evilmac.NewStateMaquina(
		&evilmac.StateMacCfg{
			StopOnError: true,
			StopOnCount: _MAX_STATES_COUNT_,
			Lg:          x.lg,
		},
	)

	if err != nil {
		x.lg.Error("error creating state machine: ", err)
		return
	}

	if err = x.registryStates(b166er); err != nil {
		x.lg.Error("error registering state: ", err)
		return
	}

	x.handhsake.Contexto.SetBuffer(handshake.CLIENTHELLO, cliHello)
	b166er.Post(handshake.CLIENTHELLO)
	if err = b166er.Start(); err != nil {
		x.lg.Error("err Handshake flow: ", err)
	}
}

func (x *xHandle) registryStates(mac evilmac.StateMac) error {

	var err error

	states := []struct {
		state evilmac.State
		id    int
	}{
		{x.handhsake.Cert, handshake.CERTIFICATE},
		{x.handhsake.CertificateReq, handshake.CERTIFICATEREQUEST},
		{x.handhsake.CertificateVerf, handshake.CERTIFICATEVERIFY},
		{x.handhsake.ChgCph, handshake.CHANGECIPHERSPEC},
		{x.handhsake.ClientHelo, handshake.CLIENTHELLO},
		{x.handhsake.ClientKeyExch, handshake.CLIENTKEYEXCHANGE},
		{x.handhsake.Finish, handshake.FINISHED},
		{x.handhsake.ServerHelo, handshake.SERVERHELLO},
		{x.handhsake.ServerHeloDone, handshake.SERVERHELLODONE},
		{x.handhsake.ServerKeyExch, handshake.SERVERKEYEXCHANGE},
		{x.handhsake.Transit, handshake.TRANSITION},
	}

	for _, s := range states {
		err = mac.Register(s.state, s.id)
		if err != nil {
			return fmt.Errorf("'%s'(%w)", s.state.Name(), err)
		}
	}

	return nil
}
