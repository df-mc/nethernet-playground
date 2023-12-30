package main

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

var key = sha256.Sum256(binary.LittleEndian.AppendUint64(nil, 0xdeadbeef))

func decryptECB(encryptedBytes []byte) ([]byte, error) {
	if len(encryptedBytes)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid blocksize: %v", len(encryptedBytes))
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	mode := ecb.NewECBDecrypter(block)
	out := make([]byte, len(encryptedBytes))
	mode.CryptBlocks(out, encryptedBytes)

	pad := padding.NewPkcs7Padding(mode.BlockSize())
	out, err = pad.Unpad(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func encryptECB(plainText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	mode := ecb.NewECBEncrypter(cipher)
	pad := padding.NewPkcs7Padding(mode.BlockSize())
	plainText, err = pad.Pad(plainText)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(plainText))
	mode.CryptBlocks(out, plainText)
	return out, nil
}
