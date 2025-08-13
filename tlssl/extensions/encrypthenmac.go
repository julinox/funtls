package extensions

type ExtExtEncryptMacData struct {
}

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
	return &ExtExtEncryptMacData{}, nil
}

func (x xExtEncryptMac) PrintRaw(data []byte) string {
	return "0x00 0x16(ExtID) 0x00 0x00(ExtLen)"
}

func (x xExtEncryptMac) PacketServerHelo(data any) ([]byte, error) {
	return []byte{0x00, 0x16, 0x00, 0x00}, nil
}
