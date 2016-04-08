package pogo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"testing"
)

func TestPKCS7PaddingValidation(t *testing.T) {
	blockSize := 16
	for i := 0; i < blockSize; i++ {
		nulls := make([]byte, i)
		valid := PKCS7Padding(nulls, blockSize)
		if err := PKCS7Validate(valid, blockSize); err != nil {
			t.Errorf("A valid padded block failed validation")
			return
		}

	}
	blockSize = 8
	i1 := []byte("ABCD\x01\x02\x03\x04")
	i2 := []byte("ABCDE\x02\x03\x03")
	i3 := []byte("ABCDE\x04\x04\x04")
	i4 := []byte("ABCDEFG\x00")
	invalids := [][]byte{i1, i2, i3, i4}
	for i, x := range invalids {
		err := PKCS7Validate(x, blockSize)
		if err == nil {
			t.Errorf("A invalid padded block passed validation (i%v)", i)
			return
		}
	}
}

func TestSplitBlocksError(t *testing.T) {
	input := []byte("ABC")
	bs := 2
	_, err := SplitBlocks(input, bs)
	if err == nil {
		t.Errorf("split blocks did not error on non-divisible block size")
		return
	}
}

func TestSplitBlocks(t *testing.T) {

	input := []byte("ABCD")
	bs := 2
	output, err := SplitBlocks(input, bs)

	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if len(output) != 2 {
		t.Errorf("split blocks had an incorrect length")
		return
	}

	if string(output[0]) != "AB" || string(output[1]) != "CD" {
		t.Errorf("blocks were not split properly")
		return
	}

	rev := MergeBlocks(output)
	if string(rev) != "ABCD" {
		t.Errorf("failed to properly merge split blocks")
		return
	}
}

func TestCBCPaddingOracle(t *testing.T) {

	key := []byte("example key 1234")
	plaintextNoPadding := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	plaintext := PKCS7Padding(plaintextNoPadding, aes.BlockSize)
	log.Printf("Plaintext %x\n", plaintext)
	log.Printf("Plaintext len %v\n", len(plaintext))
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ciphertext, plaintext)

	log.Printf("Ciphertext %x\n", ciphertext)
	log.Printf("Ciphertext len %v\n", len(ciphertext))

	oracle := func(input []byte) error {
		//log.Printf("Oracle Ciphertext %x\n", input)
		plaintext := make([]byte, len(input))
		enc := cipher.NewCBCDecrypter(block, iv)
		enc.CryptBlocks(plaintext, input)
		//log.Printf("Oracle Plaintext  %x\n", plaintext)
		if err := PKCS7Validate(plaintext, aes.BlockSize); err != nil {
			return err
		}
		return nil
	}

	verPlaintext, err := CBCPaddingOracle(ciphertext, aes.BlockSize, oracle)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	log.Printf("Decrypted plaintext %x\n", verPlaintext)
	if string(verPlaintext) != string(plaintext[aes.BlockSize:]) {
		t.Errorf("decrypted block did not match the expected plaintext")
		return
	}
}

func TestCBCPaddingOracleSingleBlock(t *testing.T) {

	key := []byte("example key 1234")
	plaintextNoPadding := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	plaintext := PKCS7Padding(plaintextNoPadding, aes.BlockSize)
	log.Printf("Plaintext %x\n", plaintext)
	log.Printf("Plaintext len %v\n", len(plaintext))
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ciphertext, plaintext)

	log.Printf("Ciphertext %x\n", ciphertext)
	log.Printf("Ciphertext len %v\n", len(ciphertext))

	oracle := func(input []byte) error {
		//log.Printf("Oracle Ciphertext %x\n", input)
		plaintext := make([]byte, len(input))
		enc := cipher.NewCBCDecrypter(block, iv)
		enc.CryptBlocks(plaintext, input)
		//log.Printf("Oracle Plaintext  %x\n", plaintext)
		if err := PKCS7Validate(plaintext, aes.BlockSize); err != nil {
			return err
		}
		return nil
	}
	blocks, err := SplitBlocks(ciphertext, aes.BlockSize)
	log.Printf("AES Block size %v\n", aes.BlockSize)
	log.Printf("Number of ciphertext blocks %v\n", len(blocks))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	log.Printf("Mod block    %x\n", blocks[0])
	log.Printf("Target block %x\n", blocks[1])
	verPlaintext, err := PaddingOracleBlockReveal(blocks, 1, oracle)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	log.Printf("Plaintext block %x\n", verPlaintext)
	if string(verPlaintext) != "AAAAAAAAAAAAAAAA" {
		t.Errorf("decrypted block did not match the expected plaintext")
		return
	}
}

func TestCBCEncryption(t *testing.T) {
	key := []byte("example key 1234")
	plaintextNoPadding := []byte("ay lmao")
	plaintext := PKCS7Padding(plaintextNoPadding, aes.BlockSize)

	if len(plaintext)%aes.BlockSize != 0 {
		t.Errorf("plaintext is not a multiple of the block size")
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	verPlaintext := make([]byte, len(ciphertext)-len(iv))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(verPlaintext, ciphertext[aes.BlockSize:])

	if string(verPlaintext) != string(plaintext) {
		t.Errorf("decrypted padded plaintext did not match expected plaintext")
		log.Printf("Expected %v | Recieved %v\n", plaintext, verPlaintext)
		return
	}

	verPlaintextNoPadding, err := PKCS7Unpadding(verPlaintext, aes.BlockSize)

	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if string(verPlaintextNoPadding) != string(plaintextNoPadding) {
		t.Errorf("decrypted unpadded plaintexted did not match expected plaintext")
		return
	}

}
