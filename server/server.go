package server

import (
	"fmt"
	"net"
	ifs "tlesio/tlssl/interfaces"
	"tlesio/tlssl/suites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

var _ENV_LOG_LEVEL_VAR_ = "TLS_LOG_LEVEL"

type serverOp struct {
	tls *zzl
	lg  *logrus.Logger
}

func RealServidor() {

	var err error
	var server serverOp

	server.lg = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	listener, err := net.Listen("tcp", port)
	if err != nil {
		server.lg.Error(err)
		return
	}

	// Init TLS Modules, Interfaces, Logger, etc
	server.tls, err = initTLS()
	if err != nil {
		server.lg.Error("TLS Init err: ", err)
		return
	}

	server.cifro()
	return
	defer listener.Close()
	server.lg.Info("Listening on PORT ", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			server.lg.Error("error accepting connection:", err)
			continue
		}

		server.lg.Info("Connection accepted from ", conn.RemoteAddr())
		go server.handleConnection(conn)
	}
}

func (server *serverOp) cifro() {

	var contexto suites.SuiteContext

	contexto.Data = []byte("holamundo")
	contexto.Key = []byte("12345678901234567890123456789012")
	contexto.IV = []byte("1234567890123456")
	contexto.HKey = []byte("macDonalds")

	// Cifro
	cipher, err := server.tls.modz.TLSSuite.GetSuite(0x003D).Cipher(&contexto)
	if err != nil {
		fmt.Println("Cifrado ERR:", err)
		return
	}

	fmt.Println("Cifrado:", cipher)
}

func (server *serverOp) handleConnection(conn net.Conn) {

	var offset uint32

	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		server.lg.Error("error reading data:", err)
		return
	}

	if n <= 5 {
		server.lg.Warning("Very little Data")
		return
	}

	hh := server.tls.ifs.TLSHead.Header(buffer)
	if hh == nil {
		server.lg.Warning("error reading header")
		return
	}

	if hh.ContentType != ifs.ContentTypeHandshake {
		server.lg.Warning("We do not negotiate with terrorist!")
		return
	}

	offset += ifs.TLS_HEADER_SIZE
	if hh.Len != len(buffer[offset:n]) {
		server.lg.Warning("Header length does not match buffer length")
		return
	}

	hs := server.tls.ifs.TLSHead.HandShake(buffer[offset:])
	if hs == nil {
		server.lg.Warning("error reading handshake")
		return
	}

	if hs.HandshakeType != ifs.HandshakeTypeClientHelo {
		server.lg.Warning("Pretty rude from you not to say helo first")
		return
	}

	offset += ifs.TLS_HANDSHAKE_SIZE
	if hs.Len != len(buffer[offset:n]) {
		server.lg.Warning("Handshake length does not match buffer length")
		return
	}

	wkf := TLSMe(server.tls, buffer[ifs.TLS_HEADER_SIZE:n], conn)
	if wkf == nil {
		return
	}

	wkf.Start()
}
