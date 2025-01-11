package extensions

type ExtensionTLS interface {
	ID() uint16
	Name() string
}

func NewExtension(extID, extLen uint16, buffer []byte) ExtensionTLS {

	// buffer should point to the beginning of the extension

	var pp ExtensionTLS
	if buffer == nil {
		return nil
	}

	pp = nil
	switch extID {
	case 0x000D: // signature_algorithms
		pp = newExtensionSignatureAlgorithms(buffer)
	}

	return pp
}
