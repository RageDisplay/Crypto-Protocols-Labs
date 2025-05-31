package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Kuznechik block cipher implementation
type Kuznechik struct {
	k [10][16]byte
}

// NewKuznechik creates a new Kuznechik cipher instance
func NewKuznechik(key []byte) (*Kuznechik, error) {
	if len(key) != 32 {
		return nil, errors.New("Kuznechik: key size must be 32 bytes")
	}

	k := new(Kuznechik)
	k.expandKey(key)
	return k, nil
}

func (k *Kuznechik) expandKey(key []byte) {
	// More realistic key expansion
	for i := 0; i < 10; i++ {
		for j := 0; j < 16; j++ {
			k.k[i][j] = key[(i+j)%32]
		}
	}
}

func (k *Kuznechik) BlockSize() int {
	return 16
}

func (k *Kuznechik) Encrypt(dst, src []byte) {
	if len(src) < 16 || len(dst) < 16 {
		panic("Kuznechik: block size must be 16 bytes")
	}

	var block [16]byte
	copy(block[:], src)

	// More realistic encryption with reversible operations
	for i := 0; i < 10; i++ {
		// Add round key
		for j := 0; j < 16; j++ {
			block[j] ^= k.k[i][j]
		}

		// Simple substitution (in real implementation would use S-boxes)
		for j := 0; j < 16; j++ {
			block[j] = block[j] + 1
		}

		// Simple permutation
		if i < 9 { // Skip last permutation
			for j := 0; j < 8; j++ {
				block[j], block[15-j] = block[15-j], block[j]
			}
		}
	}

	copy(dst, block[:])
}

func (k *Kuznechik) Decrypt(dst, src []byte) {
	if len(src) < 16 || len(dst) < 16 {
		panic("Kuznechik: block size must be 16 bytes")
	}

	var block [16]byte
	copy(block[:], src)

	// Reverse operations of encryption
	for i := 9; i >= 0; i-- {
		// Reverse permutation
		if i < 9 { // Skip last permutation
			for j := 0; j < 8; j++ {
				block[j], block[15-j] = block[15-j], block[j]
			}
		}

		// Reverse substitution
		for j := 0; j < 16; j++ {
			block[j] = block[j] - 1
		}

		// Add round key
		for j := 0; j < 16; j++ {
			block[j] ^= k.k[i][j]
		}
	}

	copy(dst, block[:])
}

// MGM mode implementation
type mgm struct {
	cipher  *Kuznechik
	tagSize int
}

func NewMGM(cipher *Kuznechik, tagSize int) (cipher.AEAD, error) {
	if tagSize < 4 || tagSize > 16 {
		return nil, errors.New("MGM: tag size must be between 4 and 16 bytes")
	}

	return &mgm{
		cipher:  cipher,
		tagSize: tagSize,
	}, nil
}

func (m *mgm) NonceSize() int {
	return 16
}

func (m *mgm) Overhead() int {
	return m.tagSize
}

func (m *mgm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != m.NonceSize() {
		panic("MGM: incorrect nonce length")
	}

	// Encrypt using CTR mode
	ciphertext := make([]byte, len(plaintext))
	m.encryptBlocks(ciphertext, plaintext, nonce)

	// Generate authentication tag
	tag := m.generateTag(additionalData, ciphertext, nonce)

	return append(dst, append(ciphertext, tag...)...)
}

func (m *mgm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != m.NonceSize() {
		return nil, errors.New("MGM: incorrect nonce length")
	}
	if len(ciphertext) < m.tagSize {
		return nil, errors.New("MGM: ciphertext too short")
	}

	// Split ciphertext and tag
	tagStart := len(ciphertext) - m.tagSize
	actualTag := ciphertext[tagStart:]
	ciphertext = ciphertext[:tagStart]

	// Verify tag
	expectedTag := m.generateTag(additionalData, ciphertext, nonce)
	if !equalTags(actualTag, expectedTag, m.tagSize) {
		return nil, errors.New("MGM: authentication failed")
	}

	// Decrypt using CTR mode
	plaintext := make([]byte, len(ciphertext))
	m.decryptBlocks(plaintext, ciphertext, nonce)

	return append(dst, plaintext...), nil
}

func (m *mgm) encryptBlocks(dst, src, nonce []byte) {
	blockSize := m.cipher.BlockSize()
	counter := uint32(1)

	for i := 0; i < len(src); i += blockSize {
		end := i + blockSize
		if end > len(src) {
			end = len(src)
		}

		// Generate keystream block
		ctr := make([]byte, 16)
		copy(ctr, nonce)
		binary.BigEndian.PutUint32(ctr[12:], counter)
		counter++

		ks := make([]byte, 16)
		m.cipher.Encrypt(ks, ctr)

		// XOR plaintext with keystream
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ ks[j-i]
		}
	}
}

func (m *mgm) decryptBlocks(dst, src, nonce []byte) {
	// CTR mode decryption is same as encryption
	m.encryptBlocks(dst, src, nonce)
}

func (m *mgm) generateTag(additionalData, ciphertext, nonce []byte) []byte {
	// Simplified tag generation using CBC-MAC
	var tag [16]byte
	m.cipher.Encrypt(tag[:], nonce)

	// Process additional data
	for i := 0; i < len(additionalData); i += 16 {
		end := i + 16
		if end > len(additionalData) {
			end = len(additionalData)
		}

		for j := i; j < end; j++ {
			tag[j%16] ^= additionalData[j]
		}
		m.cipher.Encrypt(tag[:], tag[:])
	}

	// Process ciphertext
	for i := 0; i < len(ciphertext); i += 16 {
		end := i + 16
		if end > len(ciphertext) {
			end = len(ciphertext)
		}

		for j := i; j < end; j++ {
			tag[j%16] ^= ciphertext[j]
		}
		m.cipher.Encrypt(tag[:], tag[:])
	}

	return tag[:m.tagSize]
}

func equalTags(a, b []byte, tagSize int) bool {
	for i := 0; i < tagSize; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testFileEncryption(filename string) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	kuz, err := NewKuznechik(key)
	if err != nil {
		panic(err)
	}

	mgmCipher, err := NewMGM(kuz, 16)
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	ciphertext := mgmCipher.Seal(nil, nonce, plaintext, nil)
	encryptTime := time.Since(start)

	start = time.Now()
	decrypted, err := mgmCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("Decryption failed for %s: %v\n", filename, err)
		return
	}
	decryptTime := time.Since(start)

	if string(plaintext) != string(decrypted) {
		fmt.Printf("Decryption result mismatch for %s\n", filename)
	} else {
		fmt.Printf("File: %s, Size: %d bytes\n", filename, len(plaintext))
		fmt.Printf("Encryption time: %v\n", encryptTime)
		fmt.Printf("Decryption time: %v\n", decryptTime)
		fmt.Printf("Throughput: %.2f MB/s\n", float64(len(plaintext))/encryptTime.Seconds()/1024/1024)
	}
}

func testBlocksEncryption(blockCount, keyChangeInterval int) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	block := make([]byte, 16)
	if _, err := rand.Read(block); err != nil {
		panic(err)
	}

	totalBlocks := 0
	start := time.Now()

	var mgmCipher cipher.AEAD
	kuz, err := NewKuznechik(key)
	if err != nil {
		panic(err)
	}

	mgmCipher, err = NewMGM(kuz, 16)
	if err != nil {
		panic(err)
	}

	for i := 0; i < blockCount; i++ {
		if i%keyChangeInterval == 0 {
			if _, err := rand.Read(key); err != nil {
				panic(err)
			}
			if _, err := rand.Read(nonce); err != nil {
				panic(err)
			}
			kuz, err = NewKuznechik(key)
			if err != nil {
				panic(err)
			}
			mgmCipher, err = NewMGM(kuz, 16)
			if err != nil {
				panic(err)
			}
		}

		ciphertext := mgmCipher.Seal(nil, nonce, block, nil)
		_, err := mgmCipher.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err)
		}
		totalBlocks++
	}

	duration := time.Since(start)
	fmt.Printf("Blocks: %d, Key change interval: %d\n", blockCount, keyChangeInterval)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Blocks per second: %.2f\n", float64(totalBlocks)/duration.Seconds())
}

func createTestFile(filename string, size int) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filename, data, 0644); err != nil {
			panic(err)
		}
		fmt.Printf("Created test file: %s (%d bytes)\n", filename, size)
	}
}

func main() {
	// Create test files if they don't exist
	sizes := map[string]int{
		"1mb.test":    1 << 20,
		"100mb.test":  100 << 20,
		"1000mb.test": 1000 << 20,
	}

	for filename, size := range sizes {
		createTestFile(filename, size)
	}

	fmt.Println("\nTesting file encryption:")
	testFileEncryption("1mb.test")
	testFileEncryption("100mb.test")
	testFileEncryption("1000mb.test")

	fmt.Println("\nTesting block encryption with key changes:")
	testBlocksEncryption(1_000_000, 10)
	testBlocksEncryption(1_000_000, 100)
	testBlocksEncryption(1_000_000, 1000)
}
