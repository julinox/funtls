package server

import (
	"net"

	"tlesio/tlssl"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var port = ":8443"

type serverOp struct {
	lg     *logrus.Logger
	tlsCtx *tlssl.TLSContext
	err    error // For initialization errors
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
	server.tlsCtx = &tlssl.TLSContext{}
	server.initTLSContext()
	if server.err != nil {
		server.lg.Error("TLS Init err: ", server.err)
		return
	}

	server.lg.Info("TLS Context Initialized")
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

func (server *serverOp) handleConnection(conn net.Conn) {

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

	if len(buffer[:n]) <= 45 {
		server.lg.Warning("buffer is too small for a client hello")
		return
	}

	tHeader := tlssl.TLSHead(buffer)
	if tHeader.ContentType != tlssl.ContentTypeHandshake {
		server.lg.Warning("We do not negotiate with terrorist!")
		return
	}

	if tHeader.Len != len(buffer[tlssl.TLS_HEADER_SIZE:n]) {
		server.lg.Warning("Header length does not match buffer length")
		return
	}

	tHeaderHS := tlssl.TLSHeadHandShake(buffer[tlssl.TLS_HEADER_SIZE:])
	if tHeaderHS.HandshakeType != tlssl.HandshakeTypeClientHello {
		server.lg.Warning("Pretty rude from you not to say helo first")
		return
	}

	offset := tlssl.TLS_HEADER_SIZE + tlssl.TLS_HANDSHAKE_SIZE
	if tHeaderHS.Len != len(buffer[offset:n]) {
		server.lg.Warning("Handshake length does not match buffer length")
		return
	}

	handle, _ := Handle(server.tlsCtx, conn)
	if handle == nil {
		return
	}

	handle.LetsTalk(buffer[:n])
}
