package dh

import (
	"github.com/julinox/funtls/tlssl/names"
)

type xDHClassic struct {
	supportedGroups map[uint16]bool
}

func NewModDHClassic() DiffieHellman {

	var newDHC xDHClassic

	newDHC.supportedGroups = make(map[uint16]bool)
	newDHC.supportedGroups[names.FFDHE2048] = true
	return &newDHC
}

func (x *xDHClassic) IsGroupSupported(id uint16) bool {
	return x.IsGroupSupported(id)
}
