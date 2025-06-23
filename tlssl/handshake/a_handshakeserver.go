package handshake

import (
	"fmt"
	"net"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	evilmac "github.com/julinox/statemaquina"
)

const _MAX_STATES_COUNT_SERVER_ = 1 << 4

type HandshakeServer struct {
	CliHello []byte
	Conn     net.Conn
	Tctx     *tlssl.TLSContext
}

func NewHandshakeServer(hsks *HandshakeServer) (net.Conn, error) {

	var actx AllContexts
	var newHandshake Handshake

	myself := systema.MyName()
	if hsks == nil || hsks.Conn == nil || hsks.Tctx == nil {
		return nil, fmt.Errorf("nil TLSContext/conn object(%s)", myself)
	}

	// At least a 56 bytes ClientHello (including SNI)
	if len(hsks.CliHello) < 56 {
		return nil, fmt.Errorf("ClientHello too short(%s)", myself)
	}

	// Init HandshakeContext interface
	hskCtx := NewHandShakeContext(hsks.Tctx.Lg, hsks.Conn)
	if hskCtx == nil {
		return nil, fmt.Errorf("nil HandShakeContext object(%s)", myself)
	}

	actx.Hctx = hskCtx
	actx.Tctx = hsks.Tctx
	hskCtx.SetTransitionStage(STAGE_SERVERHELLODONE)

	// Set handshake struct
	newHandshake.Contexto = hskCtx
	newHandshake.Cert = NewCertificate(&actx)
	newHandshake.CertificateReq = NewCertificateRequest(actx.Hctx)
	newHandshake.CertificateVerf = NewCertificateVerify(actx.Hctx)
	newHandshake.ChgCph = NewChangeCipherSpec(&actx)
	newHandshake.ClientHelo = NewClientHello(&actx)
	newHandshake.ClientKeyExch = NewClientKeyExchange(&actx)
	newHandshake.Finish = NewFinished(&actx)
	newHandshake.ServerHelo = NewServerHello(&actx)
	newHandshake.ServerHeloDone = NewServerHelloDone(&actx)
	newHandshake.ServerKeyExch = NewServerKeyExchange(&actx)
	newHandshake.Transit = NewTransition(&actx)
	if err := checkHandshakeInit(&newHandshake); err != nil {
		return nil, fmt.Errorf("handshake object creation: %v", err)
	}

	// Create state machine to define the handshake flow
	b166er, _ := evilmac.NewStateMaquina(
		&evilmac.StateMacCfg{
			StopOnError: true,
			StopOnCount: _MAX_STATES_COUNT_SERVER_,
			Lg:          hsks.Tctx.Lg,
		},
	)

	if err := registryStates(b166er, &newHandshake); err != nil {
		return nil, fmt.Errorf("error registering state: %w", err)
	}

	// Set buffer to the ClientHello
	newHandshake.Contexto.SetBuffer(CLIENTHELLO, hsks.CliHello)
	b166er.Post(CLIENTHELLO)
	if err := b166er.Start(); err != nil {
		hsks.Tctx.Lg.Errorf("err Handshake flow(%v): %v", myself, err)
		return nil, err
	}

	// This shouldnt happen
	if !newHandshake.Contexto.IsCompleted() {
		hsks.Tctx.Lg.Errorf("Handshake not completed(%s)", myself)
		return nil, fmt.Errorf("Handshake not completed(%s)", myself)
	}

	return tlssl.NewTLSConn(&tlssl.TLSConn{
		RawConn:   hsks.Conn,
		Lg:        hsks.Tctx.Lg,
		SpecRead:  newHandshake.Contexto.GetCipherScpec(CIPHERSPECCLIENT),
		SpecWrite: newHandshake.Contexto.GetCipherScpec(CIPHERSPECSERVER),
	})
}

func registryStates(mac evilmac.StateMac, hsk *Handshake) error {

	var err error

	if mac == nil || hsk == nil {
		return fmt.Errorf("nil mac/Handshake object")
	}

	states := []struct {
		state evilmac.State
		id    int
	}{
		{hsk.Cert, CERTIFICATE},
		{hsk.CertificateReq, CERTIFICATEREQUEST},
		{hsk.CertificateVerf, CERTIFICATEVERIFY},
		{hsk.ChgCph, CHANGECIPHERSPEC},
		{hsk.ClientHelo, CLIENTHELLO},
		{hsk.ClientKeyExch, CLIENTKEYEXCHANGE},
		{hsk.Finish, FINISHED},
		{hsk.ServerHelo, SERVERHELLO},
		{hsk.ServerHeloDone, SERVERHELLODONE},
		{hsk.ServerKeyExch, SERVERKEYEXCHANGE},
		{hsk.Transit, TRANSITION},
	}

	for _, s := range states {
		err = mac.Register(s.state, s.id)
		if err != nil {
			return fmt.Errorf("'%s'(%w)", s.state.Name(), err)
		}
	}

	return nil
}
