package modulos

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	css "github.com/julinox/funtls/tlssl/suite"

	"github.com/sirupsen/logrus"
)

type ModTLSSuite interface {
	Name() string
	IsSupported(uint16) bool
	AllSupported() []uint16
	GetSuite(uint16) css.Suite
	RegisterSuite(css.Suite) error
	PrintAll() string
	SetTax(uint16)
}

type xModTLSSuite struct {
	lg        *logrus.Logger
	supported map[uint16]css.Suite
	tax       uint16
}

func NewModTLSSuite(lg *logrus.Logger) (ModTLSSuite, error) {

	var newCS xModTLSSuite

	if lg == nil {
		return nil, systema.ErrNilParams
	}

	newCS.lg = lg
	newCS.supported = make(map[uint16]css.Suite)
	return &newCS, nil
}

func (x *xModTLSSuite) Name() string {
	return "TLS_Suites"
}

func (x *xModTLSSuite) IsSupported(id uint16) bool {

	if x.tax != 0 && id != x.tax {
		return false
	}

	return x.supported[id] != nil
}

func (x *xModTLSSuite) AllSupported() []uint16 {

	var all []uint16

	if x.tax != 0 {
		return []uint16{x.tax}
	}

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

// Tax means imposition so in this context
// it means that only the suite with this ID will be used
func (x *xModTLSSuite) SetTax(tax uint16) {

	if x.IsSupported(tax) == false {
		x.lg.Warnf("Suite (TAX) '%v' unsupported", css.CipherSuiteNames[tax])
		return
	}

	x.lg.Infof("Set(TAX) Suite: %v", css.CipherSuiteNames[tax])
	x.tax = tax
}

func (x *xModTLSSuite) PrintAll() string {

	var str string

	for _, cs := range x.supported {
		str += fmt.Sprintf("TLS Suite: %v\n", cs.Name())
	}

	return str
}
