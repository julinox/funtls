package handshake

import (
	"net"
	"tlesio/tlssl"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

type zzl struct {
	lg     *logrus.Logger
	tessio tlssl.TLS12
}

func RealServidor() {

	var ssl zzl
	var err error

	ssl.lg = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	if ssl.lg == nil {
		ssl.lg.Error("Error creating server logger")
		return
	}

	tlssl.NewTLS2(ssl.lg)
	return
	listener, err := net.Listen("tcp", port)
	if err != nil {
		ssl.lg.Error(err)
		return
	}

	defer listener.Close()
	ssl.lg.Info("Listening on PORT ", port)
	ssl.tessio, err = tlssl.NewTLSDefault()
	if err != nil {
		ssl.lg.Error("Error creating TLS Control: ", err)
		return
	}

	return
	for {
		conn, err := listener.Accept()
		if err != nil {
			ssl.lg.Error("Error accepting connection:", err)
			continue
		}

		ssl.lg.Info("Connection accepted from ", conn.RemoteAddr())
		go ssl.handleConnection(conn)
	}
}

func (ssl *zzl) handleConnection(conn net.Conn) {

	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		ssl.lg.Error("Error reading data:", err)
		return
	}

	if n <= 5 {
		ssl.lg.Warning("Very little Data")
		return
	}

	ssl.tessio.HandleTLS(buffer[:n])
}
