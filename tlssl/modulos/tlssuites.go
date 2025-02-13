package modulos

import (
	"fmt"
	"tlesio/systema"
	css "tlesio/tlssl/suites"

	"github.com/sirupsen/logrus"
)

type ModTLSSuite interface {
	Name() string
	IsSupported(uint16) bool
	AllSupported() []uint16
	GetSuite(uint16) css.Suite
	RegisterSuite(css.Suite) error
	PrintAll() string
}

type xModTLSSuite struct {
	lg        *logrus.Logger
	supported map[uint16]css.Suite
}

func NewModTLSSuite(lg *logrus.Logger) (ModTLSSuite, error) {

	var newCS xModTLSSuite

	if lg == nil {
		return nil, systema.ErrNilParams
	}

	newCS.lg = lg
	newCS.supported = make(map[uint16]css.Suite)
	newCS.lg.Info("Module loaded: ", newCS.Name())
	return &newCS, nil
}

func (x *xModTLSSuite) Name() string {
	return "TLS_Suites"
}

func (x *xModTLSSuite) IsSupported(id uint16) bool {
	return x.supported[id] != nil
}

func (x *xModTLSSuite) AllSupported() []uint16 {

	var all []uint16

	for k := range x.supported {
		all = append(all, k)
	}

	return all
}

func (x *xModTLSSuite) GetSuite(id uint16) css.Suite {

	if cs, ok := x.supported[id]; ok {
		return cs
	}

	return nil
}

func (x *xModTLSSuite) RegisterSuite(cs css.Suite) error {

	if cs == nil {
		return systema.ErrNilParams
	}

	if _, ok := x.supported[cs.ID()]; ok {
		return systema.ErrAlreadyExists
	}

	x.supported[cs.ID()] = cs
	return nil
}

func (x *xModTLSSuite) PrintAll() string {

	var str string

	for _, cs := range x.supported {
		str += fmt.Sprintf("TLS Suite: %v\n", cs.Name())
	}

	return str
}
