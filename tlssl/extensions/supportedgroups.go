package extensions

import "fmt"

const (
	// RFC 7919 - Finite Field Diffie-Hellman Ephemeral
	FFDHE2048 = 0x0100
	FFDHE3072 = 0x0101
	FFDHE4096 = 0x0102
	FFDHE6144 = 0x0103
	FFDHE8192 = 0x0104

	// RFC 7748 - Elliptic Curves
	X25519 = 0x001D
	X448   = 0x001E

	// RFC 4492 / RFC 8422 - Named Curves
	SECP256R1 = 0x0017
	SECP384R1 = 0x0018
	SECP521R1 = 0x0019

	// RFC 3526 / RFC 7919 Appendix A - MODP Groups
	MODP2048 = 0x000E
	MODP3072 = 0x000F
	MODP4096 = 0x0010
	MODP6144 = 0x0011
	MODP8192 = 0x0012
)

var SupportedGroups = map[uint16]string{
	0x000E: "modp2048",
	0x000F: "modp3072",
	0x0010: "modp4096",
	0x0011: "modp6144",
	0x0012: "modp8192",
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001D: "x25519",
	0x001E: "x448",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x0102: "ffdhe4096",
	0x0103: "ffdhe6144",
	0x0104: "ffdhe8192",
}

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
		grp := SupportedGroups[id]
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
