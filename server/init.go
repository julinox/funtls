package server

import (
	"tlesio/systema"
	iff "tlesio/tlssl/interfaces"
	mx "tlesio/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

type modulos struct {
	Cert         mx.ModCerts
	CipherSuites mx.ModCipherSuites
}

type zzl struct {
	err  error
	m0dz modulos
	lg   *logrus.Logger
	ifs  *iff.Interfaces
}

func initTLS() (*zzl, error) {

	var ssl zzl

	ssl.lg = getTLSLogger()
	ssl.m0dz.Cert = ssl.initModCerts()
	ssl.m0dz.CipherSuites = ssl.initModCipherSuites()
	return &ssl, nil
}

func (x *zzl) initModCerts() mx.ModCerts {

	certs := []*mx.CertPaths{
		{PathCert: "./certs/server.crt", PathKey: "./certs/server.key"},
		{PathCert: "./certs/server2.crt", PathKey: "./certs/server.key"},
	}

	newMod, err := mx.NewModCerts(x.lg, certs)
	if newMod == nil {
		x.err = err
		x.lg.Errorf("mod 'Certs' init err: %v", x.err)
		return nil
	}

	return newMod
}

func (x *zzl) initModCipherSuites() mx.ModCipherSuites {

	newMod, err := mx.NewModCipherSuites(&mx.CipherSuiteConfig{
		ClientWeight: 1,
		ServerWeight: 2,
		Lg:           x.lg})

	if newMod == nil {
		x.err = err
		x.lg.Errorf("mod 'CipherSUites' init err: %v", x.err)
		return nil
	}

	return newMod
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
