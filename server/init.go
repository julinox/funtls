package server

import (
	"tlesio/systema"
	hx "tlesio/tlssl/handshake"
	mx "tlesio/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

type zzl struct {
	lg    *logrus.Logger
	mods  mx.TLSModulo
	hmods *hx.HandShake
}

func initTLS() (*zzl, error) {

	var ssl zzl
	var err error

	ssl.lg = getTLSLogger()
	ssl.mods, err = mx.InitModulos(ssl.lg, getTLSModules(ssl.lg))
	if err != nil {
		ssl.lg.Error("error initializing modules: ", err)
		return nil, err
	}

	ssl.hmods, err = hx.InitHandhsakeIf(ssl.lg, ssl.mods)
	if err != nil {
		ssl.lg.Error("error initializing handshake interfaces: ", err)
		return nil, err
	}

	if ssl.mods == nil || ssl.hmods == nil {
		return nil, systema.ErrNilModulo
	}

	return &ssl, nil
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

	var basicModules []mx.ModuloInfo

	basicModules = append(basicModules, getModuleTLSHeader(lg))
	basicModules = append(basicModules, getModuleCertificateLoad(lg))
	basicModules = append(basicModules, getModuleCipherSuites(lg))
	return basicModules
}

func getModuleTLSHeader(lg *logrus.Logger) mx.ModuloInfo {

	return mx.ModuloInfo{
		Id:     0xFFFA,
		Fn:     mx.ModuleTLSHeader,
		Config: mx.ConfigTLSHeader{Lg: lg},
	}
}

func getModuleCertificateLoad(lg *logrus.Logger) mx.ModuloInfo {

	return mx.ModuloInfo{
		Id: 0xFFFE,
		Fn: mx.InitModule0xFFFE,
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
	}
}

func getModuleCipherSuites(lg *logrus.Logger) mx.ModuloInfo {

	return mx.ModuloInfo{
		Id: 0xFFFF,
		Fn: mx.InitModule0xFFFF,
	}
}
