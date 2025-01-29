package server

// -------------------------------------------
// | Field       | Size   | Description       |
// |-------------|--------|-------------------|
// | ContentType | 1 byte | Payload Type      |
// |-------------|--------|-------------------|
// | Version     | 2 bytes| TLS version       |
// |-------------|--------|-------------------|
// | Length      | 2 bytes| Length of  payload|
// -------------------------------------------

// Content Types:
// ------------------
// ChangeCipherSpec
// Alert
// Handshake
// Application Data
// ------------------

// Versions:
// ------------------
// 0x0301: TLS 1.0
// 0x0302: TLS 1.1
// 0x0303: TLS 1.2
// 0x0304: TLS 1.3a
// ------------------

import (
	"fmt"
	"net"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

var _ENV_LOG_LEVEL_VAR_ = "TLS_LOG_LEVEL"

type serverST struct {
	tls *zzl
	lg  *logrus.Logger
}

func RealServidor() {

	var err error
	var server serverST

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

func (server *serverST) handleConnection(conn net.Conn) {

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

	fmt.Println("ES handshake??")
	return
}
