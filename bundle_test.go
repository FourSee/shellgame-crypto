package shellgamecrypto

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func Test_EncryptAndSign(t *testing.T) {
	pubkeyIn, err := os.Open("./test_pub_key.asc")
	privkeyIn, _ := os.Open("./test_priv_key.asc")

	pubkeys, err := openpgp.ReadArmoredKeyRing(pubkeyIn)
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}
	privkey, err := openpgp.ReadArmoredKeyRing(privkeyIn)
	if err != nil {
		t.Errorf("Problem with privkey: %v", err)
	}

	testMessage := bytes.NewBuffer([]byte("Hello, world. This is a test message"))

	data, signature, err := EncryptAndSign(testMessage, pubkeys, privkey[0])
	if err != nil {
		t.Errorf("Problem with encryption: %v", err)
	}

	_, err = openpgp.CheckArmoredDetachedSignature(pubkeys, strings.NewReader(data), strings.NewReader(signature))
	if err != nil {
		t.Errorf("Check Detached Signature: %v", err)
	}
}
