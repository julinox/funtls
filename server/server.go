package server

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/julinox/funtls/tlssl"
	cc "github.com/julinox/funtls/tlssl/certificate"
	ex "github.com/julinox/funtls/tlssl/extensions"
	"github.com/julinox/funtls/tlssl/handshake"
	mx "github.com/julinox/funtls/tlssl/modulos"
	"github.com/julinox/funtls/tlssl/suite"
	css "github.com/julinox/funtls/tlssl/suite/ciphersuites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var _DEFAULT_PORT_ = "4433"
var (
	_ENV_LISTENING_PORT_  = "FUNTLS_PORT"
	_ENV_LOG_LEVEL_VAR_   = "FUNTLS_LOG_LEVEL"
	_ENV_CLIENT_AUTH_VAR_ = "FUNTLS_CLIENT_AUTH"
)

type FunTLSCfg struct {
	EnableClientAuth bool
	Logger           *logrus.Logger
	Certs            []*mx.CertInfo
	Certos           []*cc.CertPath
	ListeningPort    string
}

type xTLSListener struct {
	listener net.Listener
	tCtx     tlssl.TLSContext
}

// FunTLServe is the main entry point for the FunTLS server
// It initializes the TLS context and starts listening on the port
// Can handle multiple certificates, if the certificate is signed
// by a CA, the cert file should contain the full chain
func FunTLServe(cfg *FunTLSCfg) (net.Listener, error) {

	var err error
	var fun xTLSListener

	if cfg == nil {
		return nil, fmt.Errorf("FunTLSCfg is nil")
	}

	if cfg.Logger == nil {
		cfg.Logger = InitDefaultLogger()
		if cfg.Logger == nil {
			return nil, fmt.Errorf("error initializing default logger")
		}
	}

	fun.tCtx.Lg = cfg.Logger
	fun.tCtx.Certs, err = mx.NewModCerts(fun.tCtx.Lg, cfg.Certs)
	if err != nil {
		fun.tCtx.Lg.Error("error loading certificates: ", err)
		return nil, err
	}

	fun.tCtx.TLSSuite, err = initTLSSuites(fun.tCtx.Lg)
	if err != nil {
		fun.tCtx.Lg.Error("error initializing TLS suites: ", err)
		return nil, err
	}

	fun.tCtx.Exts = initExtensions(fun.tCtx.Lg)
	fun.tCtx.OptClientAuth = initClientAuthOpt()
	cfg.ListeningPort = os.Getenv(_ENV_LISTENING_PORT_)
	if cfg.ListeningPort == "" {
		cfg.ListeningPort = _DEFAULT_PORT_
	}

	// Implements the net.Listener interface
	fun.listener, err = net.Listen("tcp", ":"+cfg.ListeningPort)
	fun.tCtx.Lg.Infof("Starting FunTLS Server (%v)", fun.listener.Addr())
	return &fun, nil
}

func InitDefaultLogger() *logrus.Logger {

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

func initTLSSuites(lg *logrus.Logger) (mx.ModTLSSuite, error) {

	var err error
	var tSuite mx.ModTLSSuite

	tSuite, err = mx.NewModTLSSuite(lg)
	if err != nil {
		return nil, err
	}

	supportedSuites := map[string]suite.Suite{
		suite.CipherSuiteNames[0x0035]: css.NewRsaAes256CbcSha(),
		suite.CipherSuiteNames[0x003D]: css.NewRsaAes256CbcSha256(),
		suite.CipherSuiteNames[0x009E]: css.NewDheRsaAes128GcmSha256(),
		suite.CipherSuiteNames[0xC02B]: css.NewEcdheEcdsaAes128GcmSha256(),
	}

	for name, suite := range supportedSuites {
		if err := tSuite.RegisterSuite(suite); err != nil {
			lg.Errorf("suite '%v' registry failed: %v", name, err)
			continue
		}

		lg.Info("Suite registered: ", suite.Name())
	}

	//tSuite.SetTax(ciphersuites.NewDHE_RSA_AES_128_GCM_SHA256().ID())
	return tSuite, nil
}

func initExtensions(lg *logrus.Logger) *ex.Extensions {

	extns := ex.NewExtensions(lg)
	extns.Register(ex.NewExtSignAlgo())
	extns.Register(ex.NewExtSNI())
	extns.Register(ex.NewExtRenegotiation())
	extns.Register(ex.NewExtEncryptThenMac())
	extns.Register(ex.NewExtSupportedGroups())
	return extns
}

func initClientAuthOpt() bool {
	return strings.ToLower(os.Getenv(_ENV_CLIENT_AUTH_VAR_)) == "true"
}

/* Interface */
func (x *xTLSListener) Accept() (net.Conn, error) {

	conn, err := x.listener.Accept()
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	if n <= 5 {
		return nil, fmt.Errorf("received less than 5 bytes")
	}

	if len(buffer[:n]) <= 45 {
		return nil, fmt.Errorf("buffer is too small for a client hello")
	}

	tHeader := tlssl.TLSHead(buffer)
	if tHeader.ContentType != tlssl.ContentTypeHandshake {
		return nil, fmt.Errorf("We do not negotiate with terrorist!")
	}

	if tHeader.Len != len(buffer[tlssl.TLS_HEADER_SIZE:n]) {
		return nil, fmt.Errorf("Header len does not match buffer len")
	}

	tHeaderHS := tlssl.TLSHeadHandShake(buffer[tlssl.TLS_HEADER_SIZE:])
	if tHeaderHS.HandshakeType != tlssl.HandshakeTypeClientHello {
		return nil, fmt.Errorf("Pretty rude from you not to say helo first")
	}

	offset := tlssl.TLS_HEADER_SIZE + tlssl.TLS_HANDSHAKE_SIZE
	if tHeaderHS.Len != len(buffer[offset:n]) {
		return nil, fmt.Errorf("Handshake len does not match buffer len")
	}

	hskServer := &handshake.HandshakeServer{
		CliHello: buffer[:n],
		Conn:     conn,
		Tctx:     &x.tCtx,
	}

	x.tCtx.Lg.Info("Connection accepted from ", conn.RemoteAddr())
	return handshake.NewHandshakeServer(hskServer)
}

func (x *xTLSListener) Close() error {
	return x.listener.Close()
}

func (x *xTLSListener) Addr() net.Addr {
	return x.listener.Addr()
}
