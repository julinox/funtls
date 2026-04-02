package ftbuffer

// 17408 bytes (17KB) covers TLS 1.2 max record:
// 5 (Header) + 16384 (Payload) + 256 (Max Padding) + 48 (MAC SHA384) + 16
// (Explicit IV). Theoretical total: ~16709 bytes. 17KB allows for alignment
// and SHA512 (64).
//const MaxTLSRecordSize = 17 * 1024

func GiveMe33(sz int) []byte {
	return make([]byte, 0, sz)
}
