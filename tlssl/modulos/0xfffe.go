package modulos

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type Data0xFFFE_1 struct {
	PathCert string
	PathKey  string
}

type Config0xFFFE struct {
	Lg    *logrus.Logger
	Certs []Data0xFFFE_1
}

type Data0xFFFE struct {
	Name string
	Pkey crypto.PrivateKey
	Cert *x509.Certificate
}

type modulo0xFFFE struct {
	lg     *logrus.Logger
	config *Config0xFFFE
	pki    []*Data0xFFFE
}

func InitModule0xFFFE(cfg interface{}) (Modulo, error) {

	var modd modulo0xFFFE

	x509.ParsePKCS8PrivateKey(nil)
	data, ok := cfg.(Config0xFFFE)
	if !ok {
		return nil, fmt.Errorf("error casting Config0xFFFE")
	}

	if data.Lg == nil {
		return nil, fmt.Errorf("%v (%v)", systema.ErrNilLogger.Error(), "Modulo 0xFFFE")
	}

	modd.lg = data.Lg
	modd.config = &data
	modd.pki = make([]*Data0xFFFE, 0)
	for _, v := range data.Certs {
		data, err := modd.LoadData(v)
		if data == nil {
			modd.lg.Error("Error loading PKI: ", v.PathCert)
			continue
		}

		if err != nil {
			modd.lg.Errorf("Error loading PKI(%v): %v", v.PathCert, err.Error())
			continue
		}

		modd.pki = append(modd.pki, data.(*Data0xFFFE))
	}

	if len(modd.pki) == 0 {
		return nil, fmt.Errorf("no certificates loaded")
	}

	return &modd, nil
}

type signingAlgo struct {
	keyType string
	algo    string
}

// Receive a signing algorithm and return a matching certificate
func (e *modulo0xFFFE) Execute(data interface{}) interface{} {

	return nil
}

func (e *modulo0xFFFE) ID() uint16 {
	return 0xFFFE
}

func (e *modulo0xFFFE) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0xFFFE) GetConfig() interface{} {
	return e.config
}

// Returns *Cert0xFFFE
func (e *modulo0xFFFE) LoadData(data interface{}) (interface{}, error) {

	var err error
	var newPki Data0xFFFE

	dt, ok := data.(Data0xFFFE_1)
	if !ok {
		return nil, systema.ErrInvalidData
	}

	newPki.Cert, err = systema.LoadCertificate(dt.PathCert)
	if err != nil {
		return nil, err
	}

	newPki.Pkey, err = systema.LoadPrivateKey(dt.PathKey)
	if err != nil {
		return nil, err
	}

	if !systema.ValidateKeyPair(newPki.Cert, newPki.Pkey) {
		return nil, fmt.Errorf("invalid key pair")
	}

	newPki.Name = newPki.Cert.Subject.CommonName
	return &newPki, nil
}

func (e *modulo0xFFFE) Print() string {

	var str string

	for _, v := range e.pki {
		str += fmt.Sprintf("%v\n", v.Name)
	}

	return str
}

func (e *modulo0xFFFE) PrintRaw(data []byte) string {
	return "-*-"
}
