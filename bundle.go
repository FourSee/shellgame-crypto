package shellgamecrypto

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"

	"golang.org/x/crypto/openpgp/armor"
)

// EncryptedSignedPayload represents the signed, encrypted version of a data stream
type EncryptedSignedPayload struct {
	Data      []byte // The armored encrypted data
	Signature []byte // The armored signature payload
}

// EncryptAndSign Takes an IO stream, recipient public keys, and a non-passworded signing private key,
// then encrypts the payload and signs the result. The order is important.
// If it's signed first, THEN encrypted, the signature can't be validated without the decryption key
// This operation is destructive - the reader is no longer accessible afterwards
func EncryptAndSign(r io.Reader, recipientPubKeys []*openpgp.Entity, signingPrivKey *openpgp.Entity) (esp *EncryptedSignedPayload, err error) {

	esp = new(EncryptedSignedPayload)
	var buf bytes.Buffer
	encoder, err := armor.Encode(&buf, "Message", make(map[string]string))
	// encoder, err := armor.Encode(bytes.NewBuffer(esp.Data), "Message", make(map[string]string))

	plain, err := openpgp.Encrypt(encoder, recipientPubKeys, nil, nil, nil)

	// compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	// _, err = io.Copy(compressed, r)
	_, err = io.Copy(plain, r)
	defer encoder.Close()
	defer plain.Close()

	return esp, err
}
