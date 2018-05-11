package shellgamecrypto

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
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

	entity, err := openpgp.CheckArmoredDetachedSignature(pubkeys, strings.NewReader(data), strings.NewReader(signature))
	if err != nil {
		t.Errorf("Check Detached Signature: %v", err)
	}

	keyIDs, err := EntityKeyIDs(entity)
	if err != nil {
		t.Errorf("Error extracting key IDs from signature: %v", err)
	}

	expectedPrimaryKey := "2604AFED5E51266C"

	if keyIDs.PrimaryKeyID != expectedPrimaryKey {
		t.Errorf("Primary key mismatch. Expected: [%v] Got: [%v]", expectedPrimaryKey, keyIDs.PrimaryKeyID)
	}

	expectedSubKeys := []string{"F6B4A2643CD1CF0C"}
	if !reflect.DeepEqual(keyIDs.SubKeyIDs, expectedSubKeys) {
		t.Errorf("Subkeys mismatch. Expected: [%v] Got: [%v]", expectedSubKeys, keyIDs.SubKeyIDs)
	}

	signedArmor, _ := armor.Decode(strings.NewReader(signature))
	signerID, err := ReadSigner(signedArmor.Body)
	if err != nil {
		t.Errorf("Error extracting key ID from signature: %v", err)
	}

	if signerID != expectedPrimaryKey {
		t.Errorf("Signer ID mismatch. Expected: [%v] Got: [%v]", expectedPrimaryKey, signerID)
	}

}
