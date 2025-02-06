package extensions

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

var SupportedExtensions = map[uint16]string{
	0x000D: "signature_algorithms",
}

type ExtLoadFN func([]byte, int) (interface{}, error)
type Extensions struct {
	SignAlgo ExtSignAlgo
	table    map[uint16]ExtLoadFN
	lg       *logrus.Logger
}

func NewExtensions(lg *logrus.Logger) (*Extensions, error) {

	var newExts Extensions

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	newExts.lg = lg
	newExts.table = make(map[uint16]ExtLoadFN)
	newExts.addSignAlgo()
	return &newExts, nil
}

func (e *Extensions) GetExtLoadFn(extType uint16) ExtLoadFN {

	if fn, ok := e.table[extType]; ok {
		return fn
	}

	return nil
}

func (e *Extensions) registerExt(extType uint16, fn ExtLoadFN) error {

	if fn == nil {
		return systema.ErrNilParams
	}

	if SupportedExtensions[extType] == "" {
		return systema.ErrUnsupported
	}

	if _, ok := e.table[extType]; ok {
		return nil
	}

	e.table[extType] = fn
	e.lg.Info("Extension loaded: ", SupportedExtensions[extType])
	return nil
}

func (e *Extensions) addSignAlgo() {

	e.SignAlgo = NewExtSignAlgo()
	e.registerExt(0x000D, e.SignAlgo.MeLoad())
}
