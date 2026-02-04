package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// SaltSize is the size of the salt used for key derivation (16 bytes).
	SaltSize = 16
	// NonceSize is the GCM standard nonce size (12 bytes).
	NonceSize = 12
	// KeySize is the AES-256 key size (32 bytes).
	KeySize = 32
)

// KeyRing manages versioned encryption keys and provides key derivation.
type KeyRing struct {
	keys       map[uint16][]byte
	currentVer uint16
}

// NewKeyRing creates a KeyRing with the given versioned keys.
// currentVer must exist in keys. All keys must be 32 bytes.
func NewKeyRing(keys map[uint16][]byte, currentVer uint16) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one key required")
	}
	if _, ok := keys[currentVer]; !ok {
		return nil, errors.New("current version key not found")
	}
	for ver, key := range keys {
		if len(key) != KeySize {
			return nil, fmt.Errorf("key for version %d must be 32 bytes", ver)
		}
	}
	return &KeyRing{
		keys:       keys,
		currentVer: currentVer,
	}, nil
}

// CurrentKey returns the master key for the current version.
func (kr *KeyRing) CurrentKey() []byte {
	return kr.keys[kr.currentVer]
}

// CurrentVersion returns the current key version.
func (kr *KeyRing) CurrentVersion() uint16 {
	return kr.currentVer
}

// KeyForVersion returns the master key for the given version, or false if not found.
func (kr *KeyRing) KeyForVersion(version uint16) ([]byte, bool) {
	key, ok := kr.keys[version]
	return key, ok
}

// DeriveKey derives a 32-byte key from a master key using HKDF.
// info is used for domain separation (e.g., "nyx-message-v1" vs "nyx-file-v1").
func (kr *KeyRing) DeriveKey(masterKey, salt, info []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateSalt generates a random salt of SaltSize bytes.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateNonce generates a random nonce of NonceSize bytes.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// NewGCM creates a new GCM cipher from a 32-byte key.
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
