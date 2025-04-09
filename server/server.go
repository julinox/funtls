package server

import (
	"fmt"
	"net"
	"os"
	"strings"

	ex "github.com/julinox/funtls/tlssl/extensions"
	mx "github.com/julinox/funtls/tlssl/modulos"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/julinox/funtls/tlssl/suite/ciphersuites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var port = ":8443"
var _ENV_LOG_LEVEL_VAR_ = "FUNTLS_LOG_LEVEL"
var _CERT_PATH_VAR_ = "./certs"

type FunTLSCfg struct {
	EnableClientAuth bool
	Logger           *logrus.Logger
	Certs            []*mx.CertInfo
}

type xFunx struct {
	certs  mx.ModCerts
	suites mx.ModTLSSuite
	lg     *logrus.Logger
	extns  *ex.Extensions
}

// FunTLServe is the main entry point for the FunTLS server
// It initializes the TLS context and starts listening on the port
// Can handle multiple certificates, if the certificate is signed
// by a CA, the cert file should contain the full chain
func FunTLServe(cfg *FunTLSCfg) (net.Listener, error) {

	var err error
	var fun xFunx

	if cfg == nil {
		return nil, fmt.Errorf("FunTLSCfg is nil")
	}

	if cfg.Logger == nil {
		fun.lg = initDefaultLogger()
	}

	fun.certs, err = mx.NewModCerts2(fun.lg, cfg.Certs)
	if err != nil {
		fun.lg.Error("Error loading certificates: ", err)
		return nil, err
	}

	fun.suites, err = initTLSSuites(fun.lg)
	if err != nil {
		fun.lg.Error("Error initializing TLS suites: ", err)
		return nil, err
	}

	fun.extns = initExtensions(fun.lg)
	fun.lg.Info("Starting FunTLS Server")
	return nil, nil
}

func initDefaultLogger() *logrus.Logger {

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

	supportedSuites := []suite.Suite{
		ciphersuites.NewAES_256_CBC_SHA(),
		ciphersuites.NewAES_256_CBC_SHA256(),
	}

	for _, suite := range supportedSuites {
		if err := tSuite.RegisterSuite(suite); err != nil {
			lg.Error("Suite registry:", err)
			continue
		}

		lg.Info("Suite registered: ", suite.Name())
	}

	return tSuite, nil
}

func initExtensions(lg *logrus.Logger) *ex.Extensions {

	extns := ex.NewExtensions(lg)
	extns.Register(ex.NewExtSignAlgo())
	extns.Register(ex.NewExtSNI())
	extns.Register(ex.NewExtRenegotiation())
	return extns
}
