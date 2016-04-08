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

func CBCPaddingOracle(ciphertext []byte, blockSize int, oracle Oracle) (plaintext []byte, err error) {

	plaintext = make([]byte, 0)
	err = nil

	if len(ciphertext)%blockSize != 0 {
		err = fmt.Errorf("ciphertext was not a multiple of the block size")
		return
	}

	blocks, err := SplitBlocks(ciphertext, blockSize)

	if err != nil {
		return
	}

	for i := 1; i < len(blocks); i++ {
		var pt []byte
		pt, err = PaddingOracleBlockReveal(blocks, i, oracle)
		if err != nil {
			return
		}
		plaintext = append(plaintext, pt...)
	}
	return plaintext, nil

}

func PaddingOracleBlockReveal(blocks [][]byte, targetBlockIndex int, oracle Oracle) (plaintext []byte, err error) {

	targetBlock := blocks[targetBlockIndex]
	modBlockBackup := make([]byte, len(blocks[targetBlockIndex-1]))
	modBlock := blocks[targetBlockIndex-1]
	copy(modBlockBackup, modBlock)

	if len(blocks) <= targetBlockIndex || len(blocks) < 2 {
		err = fmt.Errorf("invalid target block index")
		return
	}

	ltb := len(targetBlock)
	lmb := len(modBlock)

	//In order to reduce the chance false positives, lets scramble the modBlock such that none of the original bytes are the same
	for i := 0; i < lmb; i++ {
		modBlock[i] = modBlock[i] + 1
	}

	//poi ("padding oracle index") keeps track of the index of the target byte
	poi := ltb - 1
	expectedPadding := byte(1)

	//intermediate state keeps tracks of the decrypted ciphertext bytes before the previous block is xor'd
	intermediateState := make([]byte, ltb)
	for poi >= 0 {
		var mb int
		for mb = 0; mb < 256; mb++ {
			modByte := byte(mb)
			modBlock[poi] = modByte
			blocks[targetBlockIndex-1] = modBlock
			ciphertext := MergeBlocks(blocks[:targetBlockIndex+1])
			err := oracle(ciphertext)
			if err == nil {

				//w00t! we found valid padding. lets add it to our known intermediate state.
				isb := modByte ^ expectedPadding
				intermediateState[poi] = isb
				expectedPadding += 1

				//If the next padding is bigger than the block size, we are done.
				if expectedPadding > byte(ltb) {
					poi--
					break
				}

				//Update our modified ciphertext block in preperation for the next expected padding
				for j := ltb - 1; j >= poi-1; j-- {
					modBlock[j] = expectedPadding ^ intermediateState[j]
				}
				poi--
				break
			}
		}

		if mb == 256 {
			err = fmt.Errorf("unable to find valid padding for the target block")
			return
		}
	}
	plaintext, err = Xor(modBlockBackup, intermediateState)
	return
}

func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return []byte{}, fmt.Errorf("cannot xor different length bytestrings")
	}
	c := make([]byte, len(a))
	for i, x := range a {
		c[i] = x ^ b[i]
	}
	return c, nil
}

func MergeBlocks(input [][]byte) []byte {
	output := make([]byte, 0)
	for _, b := range input {
		output = append(output, b...)
	}
	return output
}

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

func PKCS7Validate(input []byte, blockSize int) error {
	err := fmt.Errorf("Invalid padding")
	l := len(input)
	lb := input[l-1]

	if lb == byte(0) {
		return err
	}

	if l%blockSize != 0 {
		return err
	}

	if int(lb) > blockSize {
		return err
	}

	for i := l - 1; i > l-1-int(lb); i-- {
		if input[i] != lb {
			return err
		}
	}
	return nil
}
