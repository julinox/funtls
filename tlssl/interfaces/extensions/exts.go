package extensions

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type Extensions struct {
	SignAlgo ExtSignAlgo
}

func NewExtensions(lg *logrus.Logger) (*Extensions, error) {

	var newExts Extensions

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	newExts.SignAlgo = NewExtSignAlgo()
	lg.Info("Extension loaded: ", newExts.SignAlgo.Name())
	return &newExts, nil
}
