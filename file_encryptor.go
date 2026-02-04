package crypto

import (
	"encoding/binary"
	"errors"
	"io"
)

const fileHkdfInfo = "nyx-file-v1"

// FileEncryptor encrypts and decrypts files with versioned keys using streaming I/O.
// Output format: version(2) || salt(16) || nonce(12) || ciphertext || tag(16)
type FileEncryptor struct {
	ring *KeyRing
}

// NewFileEncryptor creates a FileEncryptor with the given versioned keys.
// currentVer must exist in keys. All keys must be 32 bytes.
func NewFileEncryptor(keys map[uint16][]byte, currentVer uint16) (*FileEncryptor, error) {
	ring, err := NewKeyRing(keys, currentVer)
	if err != nil {
		return nil, err
	}
	return &FileEncryptor{ring: ring}, nil
}

// Encrypt reads plaintext from src and writes encrypted data to dst.
// Format: version(2) || salt(16) || nonce(12) || ciphertext || tag(16)
// The entire file is read into memory for encryption. For very large files (>100MB),
// consider implementing chunked encryption.
func (e *FileEncryptor) Encrypt(dst io.Writer, src io.Reader) error {
	masterKey := e.ring.CurrentKey()

	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	key, err := e.ring.DeriveKey(masterKey, salt, []byte(fileHkdfInfo))
	if err != nil {
		return err
	}

	gcm, err := NewGCM(key)
	if err != nil {
		return err
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return err
	}

	// Read all plaintext
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Write header: version || salt || nonce
	header := make([]byte, 2+SaltSize+NonceSize)
	binary.BigEndian.PutUint16(header[0:2], e.ring.CurrentVersion())
	copy(header[2:], salt)
	copy(header[2+SaltSize:], nonce)

	if _, err := dst.Write(header); err != nil {
		return err
	}

	// Write ciphertext (includes tag)
	_, err = dst.Write(ciphertext)
	return err
}

// Decrypt reads encrypted data from src and writes plaintext to dst.
// Expects format: version(2) || salt(16) || nonce(12) || ciphertext || tag(16)
// Returns an error if the data is corrupted or the key version is unknown.
func (e *FileEncryptor) Decrypt(dst io.Writer, src io.Reader) error {
	// Read header
	header := make([]byte, 2+SaltSize+NonceSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return err
	}

	version := binary.BigEndian.Uint16(header[0:2])
	masterKey, ok := e.ring.KeyForVersion(version)
	if !ok {
		return errors.New("unknown key version")
	}

	salt := header[2 : 2+SaltSize]
	nonce := header[2+SaltSize : 2+SaltSize+NonceSize]

	key, err := e.ring.DeriveKey(masterKey, salt, []byte(fileHkdfInfo))
	if err != nil {
		return err
	}

	gcm, err := NewGCM(key)
	if err != nil {
		return err
	}

	// Read ciphertext
	ciphertext, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.New("decryption failed: invalid ciphertext or key")
	}

	_, err = dst.Write(plaintext)
	return err
}
