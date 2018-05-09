package shellgameCrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// GenerateECDSAKeyPair takes the bitlength and spits out an armored
// private/public Elliptic Curve keypair
// func GenerateECDSAKeyPair() (privKey []byte, pubKey []byte, err error) {
// 	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// 	priv.PublicKey.
// 	if err != nil {
// 		return nil, nil, err
// 	}

// }

// GenerateRSAKeyPair takes the bitlength and spits out an armored
// private/public RSA keypair
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
	err = encodePublicKey(pub, key)
	if err != nil {
		return nil, nil, err
	}

	return priv.Bytes(), pub.Bytes(), nil
}

// DecodePublicKey returns metadata about a public key
func DecodePublicKey(r io.Reader) (key *KeyIDs, err error) {

	reader := packet.NewReader(r)
	key = new(KeyIDs)

	// key, ok := pkt.(*packet.PublicKey)
	// hKey := strings.ToUpper(fmt.Sprintf("%x", key.KeyId))
	// fmt.Println(hKey)
ParsePackets:
	for {
		pkt, err := reader.Next()
		if err != nil {
			break ParsePackets
		}
		switch p := pkt.(type) {
		case *packet.PublicKey:
			hexKey := strings.ToUpper(fmt.Sprintf("%x", p.KeyId))
			if p.IsSubkey {
				key.SubKeyIDs = append(key.SubKeyIDs, hexKey)
			} else {
				key.PrimaryKeyID = hexKey
			}
		case *packet.UserId:
			key.UserID = *p
		default:
			continue
		}

	}
	return key, err
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
