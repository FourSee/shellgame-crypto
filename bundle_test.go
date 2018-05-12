package shellgamecrypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func Test_EncryptAndSign(t *testing.T) {
	pubkeyIn, err := os.Open("./test_pub_key.b64")
	privkeyIn, _ := os.Open("./test_priv_key.b64")

	pubDecoder := base64.NewDecoder(base64.StdEncoding, pubkeyIn)
	privDecoder := base64.NewDecoder(base64.StdEncoding, privkeyIn)

	pubkeys, err := openpgp.ReadKeyRing(pubDecoder)
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}
	privkey, err := openpgp.ReadKeyRing(privDecoder)
	if err != nil {
		t.Errorf("Problem with privkey: %v", err)
	}

	testMessage := bytes.NewBuffer([]byte("Hello, world. This is a test message"))

	data, signature, err := EncryptAndSign(testMessage, pubkeys, privkey[0])
	if err != nil {
		t.Errorf("Problem with encryption: %v", err)
	}

	fmt.Println("Encrypted data:")
	fmt.Println(data)
	fmt.Println("Signature:")
	fmt.Println(signature)

	entity, err := openpgp.CheckDetachedSignature(pubkeys, strings.NewReader(data), base64.NewDecoder(base64.StdEncoding, strings.NewReader(signature)))
	if err != nil {
		t.Errorf("Check Detached Signature: %v", err)
	}

	keyIDs, err := EntityKeyIDs(entity)
	if err != nil {
		t.Errorf("Error extracting key IDs from signature: %v", err)
	}

	expectedPrimaryKey := "E35BD19357C4033E"

	if keyIDs.PrimaryKeyID != expectedPrimaryKey {
		t.Errorf("Primary key mismatch. Expected: [%v] Got: [%v]", expectedPrimaryKey, keyIDs.PrimaryKeyID)
	}

	expectedSubKeys := []string{"6A7383DC331DA728"}
	if !reflect.DeepEqual(keyIDs.SubKeyIDs, expectedSubKeys) {
		t.Errorf("Subkeys mismatch. Expected: [%v] Got: [%v]", expectedSubKeys, keyIDs.SubKeyIDs)
	}

	signerID, err := ReadSigner(base64.NewDecoder(base64.StdEncoding, strings.NewReader(signature)))
	if err != nil {
		t.Errorf("Error extracting key ID from signature: %v", err)
	}

	if signerID != expectedPrimaryKey {
		t.Errorf("Signer ID mismatch. Expected: [%v] Got: [%v]", expectedPrimaryKey, signerID)
	}

}
