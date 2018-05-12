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
func GenerateRSAKeyPair(bits int, name, comment, email string) (privKey string, pubKey string, err error) {
	config := gpgeez.Config{Expiry: 3650 * 24 * time.Hour}
	config.RSABits = bits
	key, err := gpgeez.CreateKey(name, comment, email, &config)
	if err != nil {
		return
	}
	pubKey, err = armorPublic(key)

	if err != nil {
		return
	}

	privKey, err = armorPrivate(key, &config)
	if err != nil {
		return
	}

	return
}

func armorPublic(key *gpgeez.Key) (string, error) {
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	key.Serialize(encoder)
	encoder.Close()
	return buf.String(), nil
}

func armorPrivate(key *gpgeez.Key, config *gpgeez.Config) (string, error) {
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

// func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) (err error) {
// 	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
// 	if err != nil {
// 		return err
// 	}

// 	defer w.Close()
// 	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
// 	pgpKey.Serialize(w)
// 	return nil
// }

// func encodePublicKey(out io.Writer, key *rsa.PrivateKey) (err error) {
// 	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
// 	if err != nil {
// 		return err
// 	}

// 	defer w.Close()
// 	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
// 	pgpKey.Serialize(w)
// 	return nil
// }
