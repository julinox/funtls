package suites

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func padPKCS7(data []byte, blockSize int) []byte {

	if len(data) == 0 {
		return nil
	}

	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func unpadPKCS7(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("PKCS7 unpad empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}

	return data[:len(data)-padLen], nil
}

func aesCBC(data, key, iv []byte, padd bool) ([]byte, error) {

	var finalFlow []byte

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padd {
		data = padPKCS7(data, aes.BlockSize)
	}

	finalFlow = make([]byte, len(data))
	sypher := cipher.NewCBCEncrypter(block, iv)
	sypher.CryptBlocks(finalFlow, data)
	return finalFlow, nil
}
