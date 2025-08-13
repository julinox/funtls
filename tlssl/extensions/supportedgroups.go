package extensions

import (
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

type ExtSupportedGroupsData struct {
	Len    uint16
	Groups []uint16
}

type xExtSuppdGroups struct {
}

func NewExtSupportedGroups() Extension {
	return &xExtSuppdGroups{}
}

func (x *xExtSuppdGroups) Name() string {
	return "SupportedGroups"
}

func (x *xExtSuppdGroups) ID() uint16 {
	return 0x000A
}

func (x *xExtSuppdGroups) LoadData(data []byte, sz int) (interface{}, error) {

	var offset uint16 = 2
	var newData ExtSupportedGroupsData

	if len(data) < 2 || len(data) != sz || len(data)%2 != 0 {
		return nil, fmt.Errorf("invalid datalen for extension %v", x.Name())
	}

	newData.Len = uint16(data[0])<<8 | uint16(data[1])/2
	if len(data[offset:])/2 != int(newData.Len) {
		return nil, fmt.Errorf("data len mismatch for extension %v", x.Name())
	}

	newData.Groups = make([]uint16, 0)
	for i := 0; i < int(newData.Len); i++ {
		newData.Groups = append(newData.Groups,
			uint16(data[offset])<<8|uint16(data[offset+1]))
		offset += 2
	}

	return &newData, nil
}

func (x *xExtSuppdGroups) PacketServerHelo(data any) ([]byte, error) {
	//return []byte{}, nil
	return nil, nil
}

func (x *xExtSuppdGroups) PrintRaw(data []byte) string {

	var length int
	var newStr string = "{"
	var offset uint16 = 2

	if len(data) < 2 || len(data)%2 != 0 {
		return "{}"
	}

	length = int(data[0])<<8 | int(data[1])/2
	if len(data[offset:])/2 != length {
		return "Invalid Data"
	}

	for i := 0; i < length; i++ {
		id := uint16(data[offset])<<8 | uint16(data[offset+1])
		grp := names.SupportedGroups[id]
		if grp == "" {
			grp = "*"
		}

		if i == 0 {
			newStr += fmt.Sprintf("%s", grp)
		} else {
			newStr += fmt.Sprintf(", %s", grp)
		}

		offset += 2
	}

	return newStr + "}"
}
