package shellgamecrypto

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func Test_EncryptAndSign(t *testing.T) {
	in, _ := os.Open("./test_gen_key.asc")
	block, _ := armor.Decode(in)
	reader := packet.NewReader(block.Body)
	pkt, _ := reader.Next()
	key, ok := pkt.(*packet.PublicKey)

	if !ok {
		t.Errorf("Error decoding the test public key: %v, %v", ok, key)
	}

	to := createEntityFromKeys(key, nil)

	testMessage := bytes.NewBuffer([]byte("Hello, world. This is a test message"))
	// r := bytes.NewReader(testMessage)
	esp, _ := EncryptAndSign(testMessage, []*openpgp.Entity{to}, nil)

	fmt.Println(esp.Data)
}
