package modulos

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

var ExtensionName = map[uint16]string{
	0x000D: "signature_algorithms",
}

type ExtHandlerLoadFN func([]byte, int) (int, error)
type ModExtensions interface {
	Load(uint16, []byte, int) (int, error)
}

type xExtensionFNs struct {
	load ExtHandlerLoadFN
	// Other?
}

type xExtension struct {
	lg       *logrus.Logger
	handlers map[uint16]*xExtensionFNs
}

func NewModExtensions(lg *logrus.Logger) (ModExtensions, error) {

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	return &xExtension{
		lg:       lg,
		handlers: make(map[uint16]*xExtensionFNs),
	}, nil

}

func (x *xExtension) AddHandlerLoad(id uint16, load ExtHandlerLoadFN) error {

	if x.handlers[id] != nil {
		return systema.ErrAlreadyExists
	}

	x.handlers[id] = &xExtensionFNs{
		load: load,
	}

	x.lg.Infof("Extension handler added[LOAD]: %v", ExtensionName[id])
	return nil
}

func (x *xExtension) Load(id uint16, buffer []byte, len int) (int, error) {

	if x.handlers[id] == nil {
		return 0, nil
	}

	return x.handlers[id].load(buffer, len)
}
