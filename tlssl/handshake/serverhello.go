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
	x.tCtx.Lg.Tracef("Field[Random(server)]: %x", random)

	// Session ID. No session resumption
	serverHelloBuf = append(serverHelloBuf, 0x00)

	// Cipher Suite
	cs, err := x.chooseCertAndCS(msgHello)
	if err != nil {
		return err
	}

	serverHelloBuf = append(serverHelloBuf, byte(cs>>8), byte(cs))
	x.ctx.SetCipherSuite(cs)
	x.tCtx.Lg.Infof("CipherSuite: %v", suite.CipherSuiteNames[cs])

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
	// This should be set in extensions's LoadData() method
	// but the extension interface does not have access to
	// the Handshake context
	if x.ctx.GetExtension(0x0016) {
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

// Its important to know that the choosing of the cipher suite is tighly
// coupled with the choosing of the certificate.
//
// Rules/Anotations for choosing certificate (regarding a CS):
// * If KX with ECDH then SG list is required, and cert's curve must match
// one from the list. Note that when signing is required (ServerKeyExchange)
// and the CS requires an EC signing algorithm then the same curve choosed
// for KX must appears among the list of SignatureAlgorithms
//
// * For classic Diffie-Hellman no SG list is required (since it has fallback)
//
// * The cert must be signed by one of the algorithms within the SA list
// but its not a requierement to be same choosed for KX
//
// A certificate by itself does not define whether the Key Exchange (KX)
// uses static (EC)DH or ephemeral (EC)DHE. That is defined by the CS.
// In static (EC)DH, the same long-term private key is reused in every KX.
// This implies:
//   - The server must already possess the long-term (EC)DH private key
//   - Since the private key is already know then ServerKeyExchange step
//     is not needed (on the contrary ephimeral requires SKE)
//   - The certificate public key must correspond to that static private key
//   - The cert need 'KeyUsage keyAgreement0 for static (EC)DH (like RSA)
//
// In (EC)DHE, the server generates a fresh ephemeral key per handshake,
// and the certificate is only used to sign the ServerKeyExchange parameters.
// KeyAgreement is not required; DigitalSignature is enough.
func (x *xServerHello) chooseCertAndCS(cliMsg *MsgHello) (uint16, error) {

	sg := getSupportedGroups(cliMsg)
	sa := getSignatureAlgorithms(cliMsg)
	certChains := x.tCtx.Certs.GetAll()
	for _, cs := range cliMsg.CipherSuites {
		if x.tCtx.TLSSuite.IsSupported(cs) {
			gg := x.tCtx.TLSSuite.GetSuite(cs)
			if gg == nil {
				continue
			}

			for _, chain := range certChains {
				// This should never happen but...
				if len(chain) == 0 {
					continue
				}

				// First element is chain is server certificate
				if gg.AcceptsCert(sg, sa, chain[0]) {
					return cs, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("No ciphersuites match for the given clientHello")
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
