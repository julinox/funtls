package suites

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aesCBCDecrypt(data, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText := make([]byte, len(data))
	syphonFilter := cipher.NewCBCDecrypter(block, iv)
	syphonFilter.CryptBlocks(clearText, data)
	return unpaddKCS7(clearText)
}

func unpaddKCS7(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length")
	}

	return data[:len(data)-(paddingLen+1)], nil
}
