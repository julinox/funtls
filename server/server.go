package server

import (
	"net"

	"tlesio/tlssl"
	"tlesio/tlssl/handshake"

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

	if len(buffer[:n]) <= 45 {
		server.lg.Warning("buffer is too small for a client hello")
		return
	}

	ifHeader := handshake.NewHeader()
	hh := ifHeader.Header(buffer)
	if hh == nil {
		server.lg.Warning("error reading header")
		return
	}

	if hh.ContentType != handshake.ContentTypeHandshake {
		server.lg.Warning("We do not negotiate with terrorist!")
		return
	}

	offset += handshake.TLS_HEADER_SIZE
	if hh.Len != len(buffer[offset:n]) {
		server.lg.Warning("Header length does not match buffer length")
		return
	}

	hs := ifHeader.HandShake(buffer[offset:])
	if hs == nil {
		server.lg.Warning("error reading handshake")
		return
	}

	if hs.HandshakeType != handshake.HandshakeTypeClientHelo {
		server.lg.Warning("Pretty rude from you not to say helo first")
		return
	}

	offset += handshake.TLS_HANDSHAKE_SIZE
	if hs.Len != len(buffer[offset:n]) {
		server.lg.Warning("Handshake length does not match buffer length")
		return
	}

	handle, _ := Handle(server.tlsCtx, conn)
	if handle == nil {
		return
	}

	handle.LetsTalk(buffer[:n])
}
