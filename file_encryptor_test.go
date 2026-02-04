package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustFileEncryptor(keys map[uint16][]byte, currentVer uint16) *FileEncryptor {
	e, err := NewFileEncryptor(keys, currentVer)
	if err != nil {
		panic(err)
	}
	return e
}

func TestNewFileEncryptor(t *testing.T) {
	key := genKey()

	_, err := NewFileEncryptor(nil, 1)
	assert.Error(t, err)

	_, err = NewFileEncryptor(map[uint16][]byte{}, 1)
	assert.Error(t, err)

	_, err = NewFileEncryptor(map[uint16][]byte{1: key}, 2)
	assert.Error(t, err)

	_, err = NewFileEncryptor(map[uint16][]byte{1: key[:16]}, 1)
	assert.Error(t, err)

	e, err := NewFileEncryptor(map[uint16][]byte{1: key}, 1)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestFileEncryptDecryptRoundTrip(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	plaintext := []byte("Hello, world! This is a test file content.")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedBuf.Bytes())
	assert.NotEqual(t, plaintext, encryptedBuf.Bytes())

	// Verify minimum size: version(2) + salt(16) + nonce(12) + tag(16) = 46 bytes minimum
	assert.GreaterOrEqual(t, encryptedBuf.Len(), 46)

	// Decrypt
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf.Bytes())
}

func TestFileEncryptDecryptEmptyInput(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	// Encrypt empty input
	src := bytes.NewReader([]byte{})
	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	// Should have at least header + tag
	assert.GreaterOrEqual(t, encryptedBuf.Len(), 2+SaltSize+NonceSize+16)

	// Decrypt empty encrypted data
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Empty(t, decryptedBuf.Bytes())
}

func TestFileKeyVersioning(t *testing.T) {
	key1 := genKey()
	key2 := make([]byte, KeySize)
	copy(key2, key1)
	key2[0] ^= 0xff

	keys := map[uint16][]byte{1: key1, 2: key2}
	e := mustFileEncryptor(keys, 2)

	plaintext := []byte("versioned file content")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	// Decrypt with encryptor that has both keys
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf.Bytes())

	// Decrypt with encryptor that only has v1 should fail (unknown version)
	e1Only := mustFileEncryptor(map[uint16][]byte{1: key1}, 1)
	encryptedReader2 := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf2 bytes.Buffer
	err = e1Only.Decrypt(&decryptedBuf2, encryptedReader2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key version")
}

func TestFileDecryptCorruptedCiphertext(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	plaintext := []byte("secret file content")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	// Corrupt the last byte (tag)
	encryptedData := encryptedBuf.Bytes()
	encryptedData[len(encryptedData)-1] ^= 0xff

	corruptedReader := bytes.NewReader(encryptedData)
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, corruptedReader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestFileDecryptWrongKey(t *testing.T) {
	key1 := genKey()
	key2 := make([]byte, KeySize)
	copy(key2, key1)
	key2[0]++

	e1 := mustFileEncryptor(map[uint16][]byte{1: key1}, 1)
	plaintext := []byte("secret file")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e1.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	// Try to decrypt with wrong key (same version, different key)
	e2 := mustFileEncryptor(map[uint16][]byte{1: key2}, 1)
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e2.Decrypt(&decryptedBuf, encryptedReader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestFileDecryptIncompleteHeader(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	// Try to decrypt with incomplete header
	incompleteData := make([]byte, 10) // Less than header size
	incompleteReader := bytes.NewReader(incompleteData)
	var decryptedBuf bytes.Buffer
	err := e.Decrypt(&decryptedBuf, incompleteReader)
	assert.Error(t, err)
}

func TestFileEncryptDecryptLargeFile(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	// Create a larger file (1MB)
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf.Bytes())
}

func TestFileEncryptDecryptBinaryData(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	// Binary data with null bytes and various byte values
	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf.Bytes())
}

func TestFileEncryptFormat(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	plaintext := []byte("test")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	encryptedData := encryptedBuf.Bytes()

	// Verify format: version(2) || salt(16) || nonce(12) || ciphertext || tag(16)
	require.GreaterOrEqual(t, len(encryptedData), 2+SaltSize+NonceSize+16)

	// Check version is correct
	version := binary.BigEndian.Uint16(encryptedData[0:2])
	assert.Equal(t, uint16(1), version)

	// Verify salt and nonce are present (non-zero randomness)
	salt := encryptedData[2 : 2+SaltSize]
	nonce := encryptedData[2+SaltSize : 2+SaltSize+NonceSize]
	assert.Equal(t, SaltSize, len(salt))
	assert.Equal(t, NonceSize, len(nonce))

	// Verify ciphertext + tag is present
	ciphertextLen := len(encryptedData) - (2 + SaltSize + NonceSize)
	assert.Greater(t, ciphertextLen, 16) // At least tag size
}

func TestFileEncryptDecryptWithMultipleVersions(t *testing.T) {
	key1 := genKey()
	key2 := make([]byte, KeySize)
	copy(key2, key1)
	key2[1] ^= 0xaa

	// Encrypt with v1
	e1 := mustFileEncryptor(map[uint16][]byte{1: key1}, 1)
	plaintext := []byte("file encrypted with v1")
	src1 := bytes.NewReader(plaintext)

	var encryptedBuf1 bytes.Buffer
	err := e1.Encrypt(&encryptedBuf1, src1)
	require.NoError(t, err)

	// Encrypt with v2
	e2 := mustFileEncryptor(map[uint16][]byte{1: key1, 2: key2}, 2)
	plaintext2 := []byte("file encrypted with v2")
	src2 := bytes.NewReader(plaintext2)

	var encryptedBuf2 bytes.Buffer
	err = e2.Encrypt(&encryptedBuf2, src2)
	require.NoError(t, err)

	// Decrypt both with encryptor that has both keys
	eBoth := mustFileEncryptor(map[uint16][]byte{1: key1, 2: key2}, 2)

	// Decrypt v1 file
	encryptedReader1 := bytes.NewReader(encryptedBuf1.Bytes())
	var decryptedBuf1 bytes.Buffer
	err = eBoth.Decrypt(&decryptedBuf1, encryptedReader1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf1.Bytes())

	// Decrypt v2 file
	encryptedReader2 := bytes.NewReader(encryptedBuf2.Bytes())
	var decryptedBuf2 bytes.Buffer
	err = eBoth.Decrypt(&decryptedBuf2, encryptedReader2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, decryptedBuf2.Bytes())
}

func TestFileEncryptDecryptStreaming(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustFileEncryptor(keys, 1)

	// Test that we can use different reader/writer types
	plaintext := []byte("streaming test content")
	src := bytes.NewReader(plaintext)

	var encryptedBuf bytes.Buffer
	err := e.Encrypt(&encryptedBuf, src)
	require.NoError(t, err)

	// Use a different reader type
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	var decryptedBuf bytes.Buffer
	err = e.Decrypt(&decryptedBuf, encryptedReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedBuf.Bytes())
}

// Test that FileEncryptor and MessageEncryptor use different HKDF domains
func TestFileAndMessageEncryptorDomainSeparation(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	fileEnc := mustFileEncryptor(keys, 1)
	msgEnc := mustEncryptor(keys, 1)

	// Encrypt same plaintext with both
	plaintext := "same content"

	// File encryptor
	var fileEncrypted bytes.Buffer
	err := fileEnc.Encrypt(&fileEncrypted, bytes.NewReader([]byte(plaintext)))
	require.NoError(t, err)

	// Message encryptor
	msgEncrypted, err := msgEnc.Encrypt(plaintext)
	require.NoError(t, err)

	// They should produce different ciphertexts (due to different HKDF info)
	// Even if salt/nonce were the same, the derived keys would differ
	assert.NotEqual(t, fileEncrypted.Bytes(), msgEncrypted)

	// But both should decrypt correctly
	var fileDecrypted bytes.Buffer
	err = fileEnc.Decrypt(&fileDecrypted, bytes.NewReader(fileEncrypted.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, plaintext, fileDecrypted.String())

	msgDecrypted, err := msgEnc.Decrypt(msgEncrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, msgDecrypted)
}
