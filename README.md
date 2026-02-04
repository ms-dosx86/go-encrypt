# go-encrypt

Encryption library with versioned keys, HKDF key derivation, and separate encryptors for short messages and files. Uses AES-256-GCM.

## Install

```bash
go get github.com/ms-dosx86/go-encrypt
```

## Message encryption

For short strings (e.g. config values, tokens). Output is base64-encoded.

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/ms-dosx86/go-encrypt/encrypt"
)

func main() {
	// Master keys must be exactly 32 bytes (AES-256). Use crypto/rand in production.
	key := make([]byte, encrypt.KeySize)
	rand.Read(key)

	keys := map[uint16][]byte{1: key}
	enc, err := encrypt.NewMessageEncryptor(keys, 1, "my-app-messages-v1")
	if err != nil {
		panic(err)
	}

	plaintext := "sensitive data"
	encoded, err := enc.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", encoded)

	decrypted, err := enc.Decrypt(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decrypted)
}
```

## File encryption

For streams (files, network). Uses the same key format; you must pass a non-empty **HKDF info** string for domain separation (e.g. use a different string than for messages).

```go
package main

import (
	"bytes"
	"crypto/rand"
	"os"

	"github.com/ms-dosx86/go-encrypt/encrypt"
)

func main() {
	key := make([]byte, encrypt.KeySize)
	rand.Read(key)

	keys := map[uint16][]byte{1: key}
	enc, err := encrypt.NewFileEncryptor(keys, 1, "my-app-files-v1")
	if err != nil {
		panic(err)
	}

	// Encrypt: read from src, write encrypted data to dst
	src := bytes.NewReader([]byte("file contents"))
	var encrypted bytes.Buffer
	if err := enc.Encrypt(&encrypted, src); err != nil {
		panic(err)
	}

	// Decrypt: read encrypted from src, write plaintext to dst
	var decrypted bytes.Buffer
	if err := enc.Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes())); err != nil {
		panic(err)
	}

	// Or with files:
	in, _ := os.Open("secret.txt")
	defer in.Close()
	out, _ := os.Create("secret.txt.enc")
	defer out.Close()
	enc.Encrypt(out, in)
}
```

## Key versioning

You can keep multiple key versions so that older ciphertexts still decrypt after a rotation. Encryption always uses the **current** version; decryption uses the version stored in the payload.

```go
	keyV1 := make([]byte, encrypt.KeySize)
	keyV2 := make([]byte, encrypt.KeySize)
	rand.Read(keyV1)
	rand.Read(keyV2)

	keys := map[uint16][]byte{
		1: keyV1,
		2: keyV2,
	}
	// Current version for new encrypts is 2; both 1 and 2 can decrypt
	enc, err := encrypt.NewMessageEncryptor(keys, 2, "my-app-v1")
	// Encrypt(…) uses key 2
	// Decrypt(…) uses the version in the ciphertext (1 or 2)
```

## HKDF info

Both `NewMessageEncryptor` and `NewFileEncryptor` require a non-empty **hkdfInfo** string. It is used for domain separation so that the same master key produces different derived keys for different uses (e.g. messages vs files). Use different strings per context, for example:

- `"myapp-messages-v1"` for message encryptor
- `"myapp-files-v1"` for file encryptor

Same key + same `hkdfInfo` + same salt ⇒ same derived key. Different `hkdfInfo` ⇒ different key; ciphertext from one cannot be decrypted with the other.

## Constants

- `encrypt.KeySize` — 32 (AES-256)
- `encrypt.SaltSize` — 16
- `encrypt.NonceSize` — 12 (GCM)

## Message format

- **Message**: base64( version(2) ‖ salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16) ). Empty plaintext returns empty string.
- **File**: raw bytes: version(2) ‖ salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16).

## Large files

The file encryptor reads the entire source into memory for encryption. For very large files (>100MB), consider chunked encryption or a different approach.
