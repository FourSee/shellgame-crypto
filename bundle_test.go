package shellgamecrypto

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func Test_EncryptAndSign(t *testing.T) {
	in, _ := os.Open("./test_gen_key.asc")
	// block, _ := armor.Decode(in)
	// reader := packet.NewReader(block.Body)
	// pkt, _ := reader.Next()
	// key, ok := pkt.(*packet.PublicKey)

	// if !ok {
	// 	t.Errorf("Error decoding the test public key: %v, %v", ok, key)
	// }
	pubkey, err := openpgp.ReadArmoredKeyRing(in)
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}
	// to := createEntityFromKeys(key, nil)

	testMessage := bytes.NewBuffer([]byte("Hello, world. This is a test message"))
	// r := bytes.NewReader(testMessage)
	// data, _, _ := EncryptAndSign(testMessage, []*openpgp.Entity{to}, nil)
	_, _, err = EncryptAndSign(testMessage, pubkey, nil)
	if err != nil {
		t.Errorf("Problem with encryption: %v", err)
	}
}

func streamToByte(stream io.Reader) []byte {
	b, err := ioutil.ReadAll(stream)
	fmt.Printf("Error was: %v", err)
	return b
	// buf := new(bytes.Buffer)

	// buf.ReadFrom(stream)
	// return buf.Bytes()
}
