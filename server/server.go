package server

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/julinox/funtls/tlssl"

	mx "github.com/julinox/funtls/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var port = ":8443"
var _ENV_LOG_LEVEL_VAR_ = "FUNTLS_LOG_LEVEL"
var _CERT_PATH_VAR_ = "./certs"

type FunTLSCfg struct {
	EnableClientAuth bool
	Logger           *logrus.Logger
	Certs            []*mx.CertPaths
}

type xFunx struct {
	lg   *logrus.Logger
	tCtx *tlssl.TLSContext
}

// FunTLS is the main entry point for the FunTLS server
// It initializes the TLS context and starts listening on the port
// Can handle multiple certificates, if the certificate is signed
// by a CA, the cert file should contain the full chain
func FunTLS(cfg *FunTLSCfg) (net.Listener, error) {

	var err error
	var fun xFunx

	if cfg == nil {
		return nil, fmt.Errorf("FunTLSCfg is nil")
	}

	fun.lg = cfg.Logger
	if fun.lg == nil {
		fun.lg = defaultLogger()
	}

	fun.tCtx, err = startTlsContext(cfg)
	if err != nil {
		fun.lg.Error(err)
		return nil, err
	}

	fun.lg.Info("Starting FunTLS Server")
	return nil, nil
}

func startTlsContext(fun *FunTLSCfg) (*tlssl.TLSContext, error) {

	var err error
	var tlsCtx tlssl.TLSContext

	tlsCtx.Modz = mx.NewModuloZ()
	if len(fun.Certs) <= 0 {
		fun.Certs = defaultCerts()
	}

	tlsCtx.Modz.Certs, err = mx.NewModCerts2(fun.Certs)
	if err != nil {
		return nil, err
	}

	fmt.Println("STAR CTX TLS")
	return &tlsCtx, nil
}

func defaultLogger() *logrus.Logger {

	var lvl logrus.Level

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "FunTLS", TagColor: "blue"})
	if lg == nil {
		return nil
	}

	levelStr := strings.ToUpper(os.Getenv(_ENV_LOG_LEVEL_VAR_))
	switch levelStr {
	case "TRACE":
		lvl = logrus.TraceLevel
	case "DEBUG":
		lvl = logrus.DebugLevel
	case "WARN":
		lvl = logrus.WarnLevel
	case "ERROR":
		lvl = logrus.ErrorLevel
	case "FATAL":
		lvl = logrus.FatalLevel
	case "PANIC":
		lvl = logrus.PanicLevel
	default:
		lvl = logrus.InfoLevel
	}

	lg.SetLevel(lvl)
	return lg
}

func defaultCerts() []*mx.CertPaths {

	//keyName := "serverkey.pem"
	//certName := "servercert.pem"
	fmt.Println("Default certs: ", _CERT_PATH_VAR_)
	fmt.Println("No certificates provided, using default")
	return nil
}

/*listener, err := net.Listen("tcp", port)
if err != nil {
	fun.lg.Error(err)
	return nil
}

server.tlsCtx = &tlssl.TLSContext{}
server.initTLSContext()
if server.err != nil {
	server.lg.Error("TLS Init err: ", server.err)
	return nil
}

server.lg.Info("TLS Context Initialized")
return listener*/
/*defer listener.Close()
server.lg.Info("Listening on PORT ", port)
for {
	conn, err := listener.Accept()
	if err != nil {
		server.lg.Error("error accepting connection:", err)
		continue
	}

	server.lg.Info("Connection accepted from ", conn.RemoteAddr())
	go server.handleConnection(conn)
}*/

/*func (server *serverOp) handleConnection(conn net.Conn) {

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
}*/
