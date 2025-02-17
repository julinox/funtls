package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"tlesio/systema"
	ifs "tlesio/tlssl/interfaces"
	"tlesio/tlssl/suites"
)

type wkf struct {
	ssl       *zzl
	conn      net.Conn
	hsContext ifs.HandShakeContext
	buffer    []byte // Original buffer including TLS header
}

// Handle Handshake Request
func TLSMe(ssl *zzl, buff []byte, conn net.Conn) *wkf {

	var newWF wkf

	if ssl == nil || buff == nil || conn == nil {
		return nil
	}

	if len(buff) <= 45 {
		ssl.lg.Error("buffer is too small for a client hello")
		return nil
	}

	newWF.ssl = ssl
	newWF.buffer = buff
	newWF.conn = conn
	newWF.hsContext = ifs.NewHandShakeContext(ssl.lg, conn)
	return &newWF
}

func (wf *wkf) Start() {

	var err error

	wf.ssl.lg.Debugf("Starting handshake with '%v'", wf.conn.RemoteAddr())
	msgHC, err := wf.ssl.ifs.CliHelo.Handle(wf.buffer[ifs.TLS_HANDSHAKE_SIZE:])
	if err != nil {
		wf.ssl.lg.Error("client hello handle:", err)
		return
	}

	// Check TLS version (muste be 1.2[0x0303])
	if binary.BigEndian.Uint16(msgHC.Version[:]) != 0x0303 {
		wf.ssl.lg.Errorf("TLS version not supported: %.4x",
			binary.BigEndian.Uint16(msgHC.Version[:]))
		return
	}

	// Save client hello packet
	wf.hsContext.SetBuffer(ifs.CLIENT_HELLO, wf.buffer)

	// server hello message
	err = wf.pktServerHelo(msgHC)
	if err != nil {
		wf.ssl.lg.Error("server hello response packet:", err)
		return
	}

	// Certificate message
	err = wf.pktCertificate(msgHC)
	if err != nil {
		wf.ssl.lg.Error("certificate packet:", err)
		return
	}

	// Server hello done message
	err = wf.pktServerHeloDone()
	if err != nil {
		wf.ssl.lg.Error("server hello done packet:", err)
		return
	}

	suite := wf.ssl.modz.TLSSuite.GetSuite(wf.hsContext.GetCipherSuite())
	if suite == nil {
		wf.ssl.lg.Error("null/null cipher suite")
		return
	}

	switch suite.Info().KeyExchange {
	case suites.RSA:
		wf.ssl.lg.Info("es RSA, directo a la accion")

	case suites.DHE:
		wf.ssl.lg.Warn("es DHE, no implementado")

	default:
		wf.ssl.lg.Error("key exchange not supported")
		return
	}

	fmt.Println(suite.Info().Print())
}

func (wf *wkf) handleClientKeyExchange() {

	var err error

	newBuff := make([]byte, 4096)
	wf.pktServerHeloDone()
	err = wf.hsContext.Send(ifs.SERVER_HELLO | ifs.CERTIFICATE |
		ifs.SERVER_HELLO_DONE)

	if err != nil {
		wf.ssl.lg.Error("RSA process send:", err)
		return
	}

	wf.ssl.lg.Info("RSA partial handshake done")

	// Receive client key exchange
	n, err := wf.conn.Read(newBuff)
	if err != nil {
		wf.ssl.lg.Error("RSA process read:", err)
		return
	}

	fmt.Println("Received:", n, "bytes")
	fmt.Println(systema.PrettyPrintBytes(newBuff[:n]))
}
