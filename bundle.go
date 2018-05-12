package shellgamecrypto

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/openpgp"
)

// EncryptAndSign Takes an IO stream, recipient public keys, and a non-passworded signing private key,
// then encrypts the payload and signs the result. The order is important.
// If it's signed first, THEN encrypted, the signature can't be validated without the decryption key
// This operation is destructive - the reader is no longer accessible afterwards
func EncryptAndSign(r io.Reader, recipientPubKeys openpgp.EntityList, signingPrivKey *openpgp.Entity) (data, signature string, err error) {

	dataReader, err := encrypt(r, recipientPubKeys)
	if err != nil {
		return "", "", err
	}
	defer dataReader.Close()
	dataReader.Seek(0, 0)

	signBytes, err := sign(dataReader, signingPrivKey)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(readerByte(dataReader)), base64.StdEncoding.EncodeToString(signBytes), nil
}

func readerByte(r io.ReadSeeker) []byte {
	r.Seek(0, 0)
	dataBuf := new(bytes.Buffer)
	dataBuf.ReadFrom(r)
	return dataBuf.Bytes()
}

func filePrefix() string {
	ts := time.Now().Unix()
	return fmt.Sprintf(".polyrythm-%v", ts)
}

func encrypt(r io.Reader, recipientPubKeys []*openpgp.Entity) (data *os.File, err error) {
	encBuf, err := ioutil.TempFile("", filePrefix())

	if err != nil {
		return nil, err
	}
	// b64enc := base64.NewEncoder(base64.StdEncoding, encBuf)
	gpgEnc, err := openpgp.Encrypt(encBuf, recipientPubKeys, nil, nil, nil)
	gzEnc, _ := gzip.NewWriterLevel(gpgEnc, gzip.BestCompression)
	if err != nil {
		return data, err
	}
	io.Copy(gzEnc, r)
	gzEnc.Close()
	gpgEnc.Close()
	// b64enc.Close()
	return encBuf, nil
}

func sign(r io.Reader, signer *openpgp.Entity) ([]byte, error) {
	sigBuf := new(bytes.Buffer)
	// b64enc := base64.NewEncoder(base64.StdEncoding, sigBuf)
	err := openpgp.DetachSign(sigBuf, signer, r, nil)
	// b64enc.Close()
	if err != nil {
		return nil, err
	}
	return sigBuf.Bytes(), nil
}
