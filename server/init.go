package server

import (
	"os"
	"strings"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"
	sts "tlesio/tlssl/suites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var (
	_ENV_LOG_LEVEL_VAR_   = "TLS_LOG_LEVEL"
	_ENV_CLIENT_AUTH_VAR_ = "TLS_CLIENT_AUTH"
)

type TLSContext struct {
	Lg            *logrus.Logger
	Modz          *mx.ModuloZ
	Exts          *ex.Extensions
	OptClientAuth bool // Enable Client Authentication
}

func initTLSContext() (*TLSContext, error) {

	var err error
	var ctx TLSContext

	ctx.Lg = getTLSLogger()
	ctx.Modz = mx.NewModuloZ()
	if err = ctx.initModuloZ(); err != nil {
		return nil, err
	}

	ctx.Exts = ex.NewExtensions(ctx.Lg)
	ctx.initExtensions()
	ctx.OptClientAuth = getTLSClientAuthOpt()
	ctx.Lg.Info("TLS Ready")
	return &ctx, nil
}

func (x *TLSContext) initModuloZ() error {

	certs := []*mx.CertPaths{
		{PathCert: "./certs/server.crt", PathKey: "./certs/server.key"},
		{PathCert: "./certs/server2.crt", PathKey: "./certs/server.key"},
	}

	suites := []sts.Suite{
		sts.NewAES_256_CBC_SHA256(x.Lg),
	}

	x.Modz.InitTLSSuite(x.Lg, suites)
	x.Modz.InitCerts(x.Lg, certs)
	return x.Modz.CheckModInit()
}

func (x *TLSContext) initExtensions() {

	x.Exts.Register(ex.NewExtSignAlgo())
	x.Exts.Register(ex.NewExtSessionTicket())
	x.Exts.Register(ex.NewExtSNI())
	x.Exts.Register(ex.NewExtEncryptThenMac())
	x.Exts.Register(ex.NewExtRenegotiation())
}

func getTLSLogger() *logrus.Logger {

	var lvl logrus.Level

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
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

func getTLSClientAuthOpt() bool {
	return os.Getenv(_ENV_CLIENT_AUTH_VAR_) == "true"
}
