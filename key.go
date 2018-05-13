package shellgamecrypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/alokmenghrajani/gpgeez"
)

// TODO: actually create GenerateECDSAKeyPair
// GenerateECDSAKeyPair takes the bitlength and spits out a base64 encoded
// private/public Elliptic Curve keypair
// func GenerateECDSAKeyPair() (privKey []byte, pubKey []byte, err error) {
// 	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// 	priv.PublicKey.
// 	if err != nil {
// 		return nil, nil, err
// 	}

// }

// GenerateRSAKeyPair takes the bitlength and spits out a base64 encoded
// private/public RSA keypair
func GenerateRSAKeyPair(bits int, name, comment, email string) (privKey string, pubKey string, err error) {
	config := gpgeez.Config{Expiry: 3650 * 24 * time.Hour}
	config.RSABits = bits
	key, err := gpgeez.CreateKey(name, comment, email, &config)
	if err != nil {
		return
	}
	pubKey, err = b64Public(key)

	if err != nil {
		return
	}

	privKey, err = b64Private(key, &config)
	if err != nil {
		return
	}

	return
}

func b64Public(key *gpgeez.Key) (string, error) {
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	key.Serialize(encoder)
	encoder.Close()
	return buf.String(), nil
}

func b64Private(key *gpgeez.Key, config *gpgeez.Config) (string, error) {
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	c := config.Config
	key.SerializePrivate(encoder, &c)
	encoder.Close()
	return buf.String(), nil
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
