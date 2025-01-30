package server

import (
	"net"
	handshake "tlesio/tlssl/interfaces"

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

	server.tls, err = initTLS()
	if err != nil {
		server.lg.Error("Error initializing TLS: ", err)
		return
	}

	defer listener.Close()
	server.lg.Info("Listening on PORT ", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			server.lg.Error("Error accepting connection:", err)
			continue
		}

		server.lg.Info("Connection accepted from ", conn.RemoteAddr())
		go server.handleConnection(conn)
	}
}

func (server *serverOp) handleConnection(conn net.Conn) {

	var offset uint32

	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		server.lg.Error("Error reading data:", err)
		return
	}

	if n <= 5 {
		server.lg.Warning("Very little Data")
		return
	}

	hh := server.tls.ifs.TLSHead.Header(buffer)
	if hh == nil {
		server.lg.Warning("Error reading header")
		return
	}

	if hh.ContentType != handshake.ContentTypeHandshake {
		server.lg.Warning("We do not negotiate with terrorist!")
		return
	}

	offset += handshake.TLS_HEADER_SIZE
	hs := server.tls.ifs.TLSHead.HandShake(buffer[offset:])
	if hs == nil {
		server.lg.Warning("Error reading handshake")
		return
	}

	if hs.HandshakeType != handshake.HandshakeTypeClientHelo {
		server.lg.Warning("Pretty rude from you not to say helo first")
		return
	}

	offset += handshake.TLS_HANDSHAKE_SIZE
	wkf := TLSMe(server.tls, buffer, conn, offset)
	if wkf == nil {
		return
	}

	wkf.Start()
}
