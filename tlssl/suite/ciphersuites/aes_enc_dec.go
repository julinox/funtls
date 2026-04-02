package ciphersuites

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

var _AES_GCM_TAG_SZ = 16
var _AES_GCM_EXPLICIT_NONCE_SZ = 8

type aesParams struct {
	data      []byte
	key       []byte
	aad       []byte
	out       []byte
	ivOrNonce []byte
}

func aesCBCEncrypt(dst, src, key, iv []byte) ([]byte, error) {

	padLen := aes.BlockSize - (len(src) % aes.BlockSize)
	requiredLen := len(src) + padLen
	if cap(dst) < requiredLen {
		return nil, fmt.Errorf("dstLen does not meet requiredLen: %v vs %v",
			cap(dst), requiredLen)
	}

	dst = dst[:requiredLen]
	copy(dst, src)
	padding := dst[len(src):]
	padByte := byte(padLen - 1)
	for i := range padding {
		padding[i] = padByte
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	syphonFilter := cipher.NewCBCEncrypter(block, iv)
	syphonFilter.CryptBlocks(dst, dst)
	return dst, nil
}

func aesCBCEncrypt2nd(dst, src, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padLen := aes.BlockSize - (len(src) % aes.BlockSize)
	if cap(dst) < len(src)+padLen {
		dst = make([]byte, len(src)+padLen)
	}

	// Adding PKCS#7 padding
	dataPadded := append(src, bytes.Repeat([]byte{byte(padLen - 1)}, padLen)...)
	syphonFilter := cipher.NewCBCEncrypter(block, iv)
	syphonFilter.CryptBlocks(dst, dataPadded)
	return dst, nil
}

/*func aesCBCEncryptOG(dst, data, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedData := paddPKCS7(data, aes.BlockSize)
	cipherText := make([]byte, len(paddedData))
	syphonFilter := cipher.NewCBCEncrypter(block, iv)
	syphonFilter.CryptBlocks(cipherText, paddedData)
	return cipherText, nil
}*/

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

func aesGCM(pms *aesParams) (cipher.AEAD, error) {

	if pms == nil {
		return nil, fmt.Errorf("nil aes parameters")
	}

	block, err := aes.NewCipher(pms.key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm, nil
}

func aesGCMEncrypt(pms *aesParams) error {

	aesgcm, err := aesGCM(pms)
	if err != nil {
		return err
	}

	outSZ := len(pms.data) + _AES_GCM_TAG_SZ
	if cap(pms.out) < outSZ {
		pms.out = make([]byte, 0, outSZ)
	}

	// Use [:0] to reset the cursor to the beginning without losing capacity (cap).
	// Reminder: Seal performs an append internally, so it will write from index 0
	pms.out = aesgcm.Seal(pms.out[:0], pms.ivOrNonce, pms.data, pms.aad)
	return nil
}

func aesGCMDecrypt(pms *aesParams) error {

	aesgcm, err := aesGCM(pms)
	if err != nil {
		return err
	}

	if len(pms.data) < _AES_GCM_TAG_SZ {
		return fmt.Errorf("ciphertext too short")
	}

	outSZ := len(pms.data) - _AES_GCM_TAG_SZ
	if cap(pms.out) < outSZ {
		pms.out = make([]byte, 0, outSZ)
	}

	// Use [:0] to reset the cursor to the beginning without losing capacity.
	// Open() performs an append internally, so it will write from index 0
	pms.out, err = aesgcm.Open(pms.out[:0], pms.ivOrNonce, pms.data, pms.aad)
	return err
}

func paddPKCS7(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(padLen - 1)}, padLen)...)
}

func paddPKCS72(data []byte, blockSize int) []byte {

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
