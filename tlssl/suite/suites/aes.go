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

func aesCBC(data, key, iv []byte, crypt bool) ([]byte, error) {

	var thText []byte
	var sypher cipher.BlockMode

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if crypt {
		thText = padPKCS7(data, aes.BlockSize)
		sypher = cipher.NewCBCEncrypter(block, iv)
	} else {
		thText = data
		sypher = cipher.NewCBCDecrypter(block, iv)
	}

	finalFlow := make([]byte, len(thText))
	sypher.CryptBlocks(finalFlow, thText)
	if !crypt {
		return unpadPKCS7(finalFlow)
	}

	return finalFlow, nil
}
