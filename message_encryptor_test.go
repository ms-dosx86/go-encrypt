package encrypt

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHKDFInfo = "nyx-message-v1"

func mustEncryptor(keys map[uint16][]byte, currentVer uint16) *MessageEncryptor {
	e, err := NewMessageEncryptor(keys, currentVer, testHKDFInfo)
	if err != nil {
		panic(err)
	}
	return e
}

func genKey() []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = byte(len(k) - i)
	}
	return k
}

func TestNewMessageEncryptor(t *testing.T) {
	key := genKey()

	_, err := NewMessageEncryptor(nil, 1, testHKDFInfo)
	assert.Error(t, err)

	_, err = NewMessageEncryptor(map[uint16][]byte{}, 1, testHKDFInfo)
	assert.Error(t, err)

	_, err = NewMessageEncryptor(map[uint16][]byte{1: key}, 2, testHKDFInfo)
	assert.Error(t, err)

	_, err = NewMessageEncryptor(map[uint16][]byte{1: key[:16]}, 1, testHKDFInfo)
	assert.Error(t, err)

	_, err = NewMessageEncryptor(map[uint16][]byte{1: key}, 1, "")
	assert.Error(t, err)

	e, err := NewMessageEncryptor(map[uint16][]byte{1: key}, 1, testHKDFInfo)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustEncryptor(keys, 1)

	plaintext := "Hello, world!"
	encrypted, err := e.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := e.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptEmptyString(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustEncryptor(keys, 1)

	encrypted, err := e.Encrypt("")
	require.NoError(t, err)
	assert.Empty(t, encrypted)

	decrypted, err := e.Decrypt("")
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestKeyVersioning(t *testing.T) {
	key1 := genKey()
	key2 := make([]byte, KeySize)
	copy(key2, key1)
	key2[0] ^= 0xff

	keys := map[uint16][]byte{1: key1, 2: key2}
	e := mustEncryptor(keys, 2)

	plaintext := "versioned message"
	encrypted, err := e.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := e.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with encryptor that only has v1 should fail (unknown version returns passthrough)
	e1Only := mustEncryptor(map[uint16][]byte{1: key1}, 1)
	out, err := e1Only.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, encrypted, out)
}

func TestDecryptLegacyPassthrough(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustEncryptor(keys, 1)

	legacy := "plain text message"
	out, err := e.Decrypt(legacy)
	require.NoError(t, err)
	assert.Equal(t, legacy, out)

	// Invalid base64 but valid length-ish: still passthrough
	out, err = e.Decrypt("not-valid-base64!!!")
	require.NoError(t, err)
	assert.Equal(t, "not-valid-base64!!!", out)
}

func TestDecryptCorruptedCiphertext(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}
	e := mustEncryptor(keys, 1)

	encrypted, err := e.Encrypt("secret")
	require.NoError(t, err)

	data, _ := base64.StdEncoding.DecodeString(encrypted)
	data[len(data)-1] ^= 0xff
	corrupted := base64.StdEncoding.EncodeToString(data)

	_, err = e.Decrypt(corrupted)
	assert.Error(t, err)
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := genKey()
	key2 := make([]byte, KeySize)
	copy(key2, key1)
	key2[0]++

	e1 := mustEncryptor(map[uint16][]byte{1: key1}, 1)
	encrypted, err := e1.Encrypt("secret")
	require.NoError(t, err)

	e2 := mustEncryptor(map[uint16][]byte{1: key2}, 1)
	_, err = e2.Decrypt(encrypted)
	assert.Error(t, err)
}

func TestMessageEncryptorCustomHKDFInfo(t *testing.T) {
	keys := map[uint16][]byte{1: genKey()}

	encCustom, err := NewMessageEncryptor(keys, 1, "my-domain-v1")
	require.NoError(t, err)
	encOther, err := NewMessageEncryptor(keys, 1, testHKDFInfo)
	require.NoError(t, err)

	plaintext := "secret message"
	encrypted, err := encCustom.Encrypt(plaintext)
	require.NoError(t, err)

	// Same HKDF info: decrypt succeeds
	decrypted, err := encCustom.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Different HKDF info: decrypt fails (different derived key)
	_, err = encOther.Decrypt(encrypted)
	assert.Error(t, err)
}
