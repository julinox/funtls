package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/julinox/funtls/tlssl"
	ex "github.com/julinox/funtls/tlssl/extensions"
	"github.com/julinox/funtls/tlssl/suite"
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

	var cipherSuite uint16
	var serverHelloBuf []byte
	var certParams *suite.CertSelection

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	msgHello := x.ctx.GetMsgHello()
	if msgHello == nil {
		return fmt.Errorf("%v: nil MsgHello object", x.Name())
	}

	serverHelloBuf = make([]byte, 0)
	// Version
	serverHelloBuf = append(serverHelloBuf, x.setVersion()...)

	// Random
	random, err := x.random()
	if err != nil {
		return fmt.Errorf("%v: error generating server random: %v",
			err, x.Name())
	}

	serverHelloBuf = append(serverHelloBuf, random[:]...)
	x.tCtx.Lg.Tracef("Field[Random(server)]: %x", random)

	// Session ID. No session resumption
	serverHelloBuf = append(serverHelloBuf, 0x00)

	//-----------------------------------------------------------------------
	// Select Cipher Suite
	certCritera := &suite.CertCriteria{
		SG:  getSupportedGroups(msgHello),
		SA:  getSignatureAlgorithms(msgHello),
		Sni: getServerNameIndication(msgHello),
	}

	for _, csc := range msgHello.CipherSuites {
		cst := x.tCtx.TLSSuite.GetSuite(csc)
		if cst == nil {
			continue
		}

		aux := cst.CertMe(certCritera)
		if aux != nil {
			cipherSuite = csc
			certParams = aux
			break
		}
	}

	if cipherSuite == 0 {
		return fmt.Errorf("%v: no matched ciphersuite", x.Name())
	}

	if certParams == nil {
		return fmt.Errorf("%v: cert selection params nil", x.Name())
	}

	x.ctx.SetCipherSuite(cipherSuite)
	x.ctx.SetCertFingerprint(certParams.Fingerprint)
	x.ctx.SetGroup(certParams.Group)
	x.ctx.SetSignatureAlgorithm(certParams.SignatureAlgorithm)
	serverHelloBuf = append(serverHelloBuf, byte(cipherSuite>>8),
		byte(cipherSuite))
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

	// Encrypt-then-MAC extension
	// Set ETM mode always when the client supports it
	//if x.ctx.GetExtension(0x0016) {
	if x.ctx.GetExtension(ex.EXT_ENCRYPT_THEN_MAC) {
		x.ctx.SetMacMode(tlssl.MODE_ETM)
		x.tCtx.Lg.Info("Encrypt-then-MAC extension enabled")
	}

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
			x.tCtx.Lg.Warnf("nil (or missing data) for Extension: %v",
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
		x.ctx.SetExtension(ext.ID())
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

func getSupportedGroups(cliMsg *MsgHello) []uint16 {

	if cliMsg == nil {
		return []uint16{}
	}

	sgAux := cliMsg.Extensions[ex.EXT_SUPPORTED_GROUPS]
	if sgAux == nil {
		return []uint16{}
	}

	sgData, ok := sgAux.(*ex.ExtSupportedGroupsData)
	if !ok {
		return []uint16{}
	}

	return sgData.Groups
}

func getSignatureAlgorithms(cliMsg *MsgHello) []uint16 {

	if cliMsg == nil {
		return []uint16{}
	}

	saAux := cliMsg.Extensions[ex.EXT_SIGNATURE_ALGORITHMS]
	if saAux == nil {
		return []uint16{}
	}

	saData, ok := saAux.(*ex.ExtSignAlgoData)
	if !ok {
		return []uint16{}
	}

	return saData.Algos
}

func getServerNameIndication(cliMsg *MsgHello) []string {

	names := []string{}
	if cliMsg == nil {
		return names
	}

	sniAux := cliMsg.Extensions[ex.EXT_SERVER_NAME]
	if sniAux == nil {
		return names
	}

	sniData, ok := sniAux.(*ex.ExtSNIData)
	if !ok {
		return names
	}

	for _, name := range sniData.Names {
		names = append(names, name.Name)
	}
	return names
}
