package shell_crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func GenerateECDSAKeyPair() {

}

// GenerateKey takes the bitlength
func GenerateRSAKeyPair(bits int) (privKey []byte, pubKey []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	priv := new(bytes.Buffer)
	err = encodePrivateKey(priv, key)
	if err != nil {
		return nil, nil, err
	}

	pub := new(bytes.Buffer)
	err = encodePrivateKey(pub, key)
	if err != nil {
		return nil, nil, err
	}

	return priv.Bytes(), pub.Bytes(), nil
}

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) (err error) {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	if err != nil {
		return err
	}

	defer w.Close()
	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	pgpKey.Serialize(w)
	return nil
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) (err error) {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		return err
	}

	defer w.Close()
	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	pgpKey.Serialize(w)
	return nil
}
