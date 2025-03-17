package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	thps "tlesio/server"
)

func main() {
	thps.RealServidor()
}

func main2() {

	key := "067d3b3db13874dcd6bf1a6019ca32c0e99a205c60f9dca021db75199b3602c6"
	iv := "9b70dafc614106000ee77947193f3cd2"
	cipherText := "842e530316f7f3fd52d0a7fc221ef4c0f88936be8c3e20ad821ca5e746da4f1ec6caf2dbec9792354cd66af48879338758edeca38cfd02fb8e37c3e8a6cdc25e59ea64df4f8d36fc36faf853b782732a"

	ct, err := decryptTLS003D(cipherText, key, iv)
	if err != nil {
		fmt.Println("ERRARSIO:", err)
		return
	}

	fmt.Printf("ClearText: %x\n", ct)
}

func decryptTLS003D(ciphertextHex string, serverKeyHex string, serverIVHex string) ([]byte, error) {
	// Convertir de HEX a []byte
	ciphertext, _ := hex.DecodeString(ciphertextHex)
	serverKey, _ := hex.DecodeString(serverKeyHex)
	serverIV, _ := hex.DecodeString(serverIVHex)

	// Crear el cifrador AES-256-CBC
	block, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, fmt.Errorf("error creando el cifrador AES: %v", err)
	}

	// Verificar que el ciphertext es múltiplo de 16 (bloques AES)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext no es múltiplo de %d bytes", aes.BlockSize)
	}

	// Crear el modo CBC
	mode := cipher.NewCBCDecrypter(block, serverIV)

	// Desencriptar en el mismo buffer
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Retornar el texto descifrado
	return decrypted, nil
}

//https://crypto.stackexchange.com/questions/113380/hash-calculation-for-tls-1-2-finished-message
//https://crypto.stackexchange.com/questions/28948/what-could-be-the-problem-with-this-tls-1-2-client-finished-message-approach
