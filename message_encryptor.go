package encrypt

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// minEncryptedSize is the minimum length of decoded payload: version(2) + salt(16) + nonce(12) + 1 byte + tag(16)
const minEncryptedSize = 2 + SaltSize + NonceSize + 1 + 16

// MessageEncryptor encrypts and decrypts message content with versioned keys.
type MessageEncryptor struct {
	ring     *KeyRing
	hkdfInfo string
}

// NewMessageEncryptor creates a MessageEncryptor with the given versioned keys.
// currentVer must exist in keys. hkdfInfo is the HKDF domain separation string and must be non-empty.
func NewMessageEncryptor(keys map[uint16][]byte, currentVer uint16, hkdfInfo string) (*MessageEncryptor, error) {
	if hkdfInfo == "" {
		return nil, errors.New("hkdfInfo must be non-empty")
	}
	ring, err := NewKeyRing(keys, currentVer)
	if err != nil {
		return nil, err
	}
	return &MessageEncryptor{ring: ring, hkdfInfo: hkdfInfo}, nil
}

func (e *MessageEncryptor) deriveKey(masterKey, salt []byte) ([]byte, error) {
	return e.ring.DeriveKey(masterKey, salt, []byte(e.hkdfInfo))
}

// Encrypt encrypts plaintext with the current key version.
// Returns base64(version:2 || salt:16 || nonce:12 || ciphertext || tag).
// Empty plaintext returns empty string.
func (e *MessageEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	masterKey := e.ring.CurrentKey()

	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}

	key, err := e.deriveKey(masterKey, salt)
	if err != nil {
		return "", err
	}

	gcm, err := NewGCM(key)
	if err != nil {
		return "", err
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	result := make([]byte, 2+SaltSize+NonceSize+len(ciphertext))
	binary.BigEndian.PutUint16(result[0:2], e.ring.CurrentVersion())
	copy(result[2:], salt)
	copy(result[2+SaltSize:], nonce)
	copy(result[2+SaltSize+NonceSize:], ciphertext)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts a base64-encoded ciphertext.
// If the payload is not valid encrypted data (e.g. legacy plaintext), returns content as-is and nil error.
func (e *MessageEncryptor) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) < minEncryptedSize {
		return encoded, nil
	}

	version := binary.BigEndian.Uint16(data[0:2])
	masterKey, ok := e.ring.KeyForVersion(version)
	if !ok {
		return encoded, nil
	}

	salt := data[2 : 2+SaltSize]
	nonce := data[2+SaltSize : 2+SaltSize+NonceSize]
	ciphertext := data[2+SaltSize+NonceSize:]

	key, err := e.deriveKey(masterKey, salt)
	if err != nil {
		return "", err
	}

	gcm, err := NewGCM(key)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: invalid ciphertext or key")
	}

	return string(plaintext), nil
}
