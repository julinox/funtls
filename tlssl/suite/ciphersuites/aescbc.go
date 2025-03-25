package ciphersuites

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aesCBCEncrypt(data, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedData := paddPKCS7(data, aes.BlockSize)
	cipherText := make([]byte, len(paddedData))
	syphonFilter := cipher.NewCBCEncrypter(block, iv)
	syphonFilter.CryptBlocks(cipherText, paddedData)
	return cipherText, nil
}

func aesCBCDecrypt(data, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	clearText := make([]byte, len(data))
	syphonFilter := cipher.NewCBCDecrypter(block, iv)
	syphonFilter.CryptBlocks(clearText, data)
	return unpaddPKCS7(clearText)
}

func paddPKCS7(data []byte, blockSize int) []byte {

	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}

	padLen -= 1
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	padding = append(padding, byte(padLen))
	return append(data, padding...)
}

func unpaddPKCS7(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length")
	}

	return data[:len(data)-(paddingLen)-1], nil
}
