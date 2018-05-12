package shellgamecrypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// EncryptAndSign Takes an IO stream, recipient public keys, and a non-passworded signing private key,
// then encrypts the payload and signs the result. The order is important.
// If it's signed first, THEN encrypted, the signature can't be validated without the decryption key
// This operation is destructive - the reader is no longer accessible afterwards
func EncryptAndSign(r io.Reader, recipientPubKeys openpgp.EntityList, signingPrivKey *openpgp.Entity) (data, signature string, err error) {
	data, err = encrypt(r, recipientPubKeys)
	if err != nil {
		return "", "", err
	}

	signature, err = sign(strings.NewReader(data), signingPrivKey)
	if err != nil {
		return "", "", err
	}

	return data, signature, nil
}

func encrypt(r io.Reader, recipientPubKeys []*openpgp.Entity) (data string, err error) {
	encBuf := new(bytes.Buffer)

	b64enc := base64.NewEncoder(base64.StdEncoding, encBuf)
	// bzEnc :=
	gpgEnc, err := openpgp.Encrypt(b64enc, recipientPubKeys, nil, nil, nil)
	if err != nil {
		return data, err
	}
	io.Copy(gpgEnc, r)
	gpgEnc.Close()
	b64enc.Close()
	return encBuf.String(), nil
}

func sign(r io.Reader, signer *openpgp.Entity) (string, error) {
	sigBuf := new(bytes.Buffer)
	b64enc := base64.NewEncoder(base64.StdEncoding, sigBuf)
	err := openpgp.DetachSign(b64enc, signer, r, nil)
	b64enc.Close()
	if err != nil {
		return "", err
	}
	return sigBuf.String(), nil
}
