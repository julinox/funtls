package server

import (
	"fmt"
	"net"
	"reflect"
	"tlesio/systema"
	"tlesio/tlssl"
	"tlesio/tlssl/handshake"

	evilmac "github.com/julinox/statemaquina"
	"github.com/sirupsen/logrus"
)

type xHandle struct {
	lg        *logrus.Logger
	handhsake *handshake.Handshake
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

	handshakeCtx.SetOptClientAuth(ctx.OptClientAuth)
	newHandle.handhsake, err = handshake.NewHandshake(handshakeCtx)
	if err != nil {
		ctx.Lg.Error(err)
		return nil, err
	}

	newHandle.lg = ctx.Lg
	// Save client hello message
	return &newHandle, nil
}

func (x *xHandle) LetsTalk(cliHello []byte) {

	var err error

	fieldsLen := reflect.TypeOf(x.handhsake).Elem().NumField()
	b166er, err := evilmac.NewStateMaquina(
		&evilmac.StateMacCfg{
			StopOnError: true,
			StopOnCount: fieldsLen,
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

	b166er.Post(handshake.CLIENTHELLO)
	b166er.Start()
}

func (x *xHandle) registryStates(mac evilmac.StateMac) error {

	var err error

	states := []struct {
		state evilmac.State
		id    int
	}{
		{x.handhsake.Cert, handshake.CERTIFICATE},
		{x.handhsake.CertRequest, handshake.CERTIFICATEREQUEST},
		{x.handhsake.ChgCph, handshake.CHANGECIPHERSPEC},
		{x.handhsake.ClientHelo, handshake.CLIENTHELLO},
		{x.handhsake.ClientKeyExch, handshake.CLIENTKEYEXCHANGE},
		{x.handhsake.Finish, handshake.FINISHED},
		{x.handhsake.ServerHelo, handshake.SERVERHELLO},
		{x.handhsake.ServerHeloDone, handshake.SERVERHELLODONE},
		{x.handhsake.ServerKeyExch, handshake.SERVERKEYEXCHANGE},
	}

	for _, s := range states {
		err = mac.Register(s.state, s.id)
		if err != nil {
			return fmt.Errorf("'%s'(%w)", s.state.Name(), err)
		}
	}

	return nil
}
