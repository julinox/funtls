package handshake

import (
	"net"
	"tlesio/systema"
	"tlesio/tlssl"
	mx "tlesio/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

var _ENV_LOG_LEVEL_VAR_ = "TLS_LOG_LEVEL"

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

	tlsLog := getTLSLogger()
	if tlsLog == nil {
		ssl.lg.Error("Error creating TLS Logger")
		return
	}

	listener, err := net.Listen("tcp", port)
	if err != nil {
		ssl.lg.Error(err)
		return
	}

	defer listener.Close()
	ssl.lg.Info("Listening on PORT ", port)
	ssl.tessio, err = tlssl.NewTLS(tlsLog, getTLSModules(tlsLog))
	if err != nil {
		ssl.lg.Error("Error creating TLS Control: ", err)
		return
	}

	if true {
		return
	}

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

func getTLSLogger() *logrus.Logger {

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		return nil
	}

	lg.SetLevel(systema.GetLogLevel(_ENV_LOG_LEVEL_VAR_))
	return lg
}

func getTLSModules(lg *logrus.Logger) []mx.ModuloInfo {

	var basicModules = []mx.ModuloInfo{

		// certificate_load

		{Id: 0xFFFF, Fn: mx.InitModule0xFFFF},
		{Id: 0x000D, Fn: mx.InitModule0x000D},
		{Id: 0xFFFE, Fn: mx.InitModule0xFFFE,
			Config: mx.Config0xFFFE{
				Lg: lg,
				Certs: []mx.Data0xFFFE_1{{
					PathCert: "./certs/server.crt",
					PathKey:  "./certs/server.key",
				}, {
					PathCert: "./certs/server2.crt",
					PathKey:  "./certs/server.key"},
				},
			},
		},
	}

	return basicModules
}
