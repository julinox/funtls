package extensions

type xExtEncryptMac struct {
}

func NewExtEncryptThenMac() Extension {
	return &xExtEncryptMac{}
}

func (x xExtEncryptMac) Name() string {
	return ExtensionName[x.ID()]
}

func (x xExtEncryptMac) ID() uint16 {
	return 0x0016
}

func (x xExtEncryptMac) LoadData(data []byte, sz int) (interface{}, error) {

	return nil, nil
}

func (x xExtEncryptMac) PrintRaw(data []byte) string {
	return ""
}

func (x xExtEncryptMac) PacketServerHelo(data interface{}) ([]byte, error) {
	return []byte{0x00, 0x16, 0x00, 0x00}, nil
}
