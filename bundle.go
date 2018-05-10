package shellgamecrypto

import (
	"bytes"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"

	"golang.org/x/crypto/openpgp/armor"
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
	msg, err := armor.Encode(encBuf, "PGP MESSAGE", nil)
	if err != nil {
		return data, err
	}
	gpg, err := openpgp.Encrypt(msg, recipientPubKeys, nil, nil, nil)
	if err != nil {
		return data, err
	}
	io.Copy(gpg, r)
	gpg.Close()
	msg.Close()
	return encBuf.String(), nil
}

func sign(r io.Reader, signer *openpgp.Entity) (string, error) {
	sigBuf := new(bytes.Buffer)
	err := openpgp.ArmoredDetachSignText(sigBuf, signer, r, nil)
	if err != nil {
		return "", err
	}

	return sigBuf.String(), nil
}
