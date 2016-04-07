package pogo

import (
	"bytes"
	"fmt"
)

//Oracle is a type synonym that represents a padding oracle.
//Oracle should take in pogo's input bytes and return an error
//if there was a padding validation error. Otherwise, it should
//return nil.
type Oracle func([]byte) error
type Padding func([]byte, int) []byte
type Unpadding func([]byte, int) ([]byte, error)

func SplitBlocks(input []byte, blockSize int) (blocks [][]byte, err error) {

	if len(input)%blockSize != 0 {
		err = fmt.Errorf("input is not a multiple of the block size")
		return
	}

	blocks = make([][]byte, len(input)/blockSize)
	for i := 0; i < len(input); i += blockSize {
		j := i + blockSize
		block := input[i:j]
		blocks[i/blockSize] = block
	}

	return blocks, nil
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	srcLen := len(src)
	padLen := blockSize - (srcLen % blockSize)
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padText...)
}

func PKCS7Unpadding(src []byte, blockSize int) ([]byte, error) {
	srcLen := len(src)
	paddingLen := int(src[srcLen-1])
	if paddingLen >= srcLen || paddingLen > blockSize {
		return nil, fmt.Errorf("padding size error")
	}
	return src[:srcLen-paddingLen], nil
}
