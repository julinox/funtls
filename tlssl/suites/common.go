package suites

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func padPKCS7(data []byte, blockSize int) []byte {

	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func unpadPKCS7(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}

	return data[:len(data)-padLen], nil
}

func aesCBC(clearText, key, iv []byte) ([]byte, error) {

	var cipherText []byte

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedClearText := padPKCS7(clearText, aes.BlockSize)
	cipherText = make([]byte, len(paddedClearText))
	sypher := cipher.NewCBCEncrypter(block, iv)
	sypher.CryptBlocks(cipherText, paddedClearText)
	return cipherText, nil
}
