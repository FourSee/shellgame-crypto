package shellgamecrypto

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func Test_EncryptAndSign(t *testing.T) {
	plaintextMessage := "Hello, world. This is a test message"
	recipientPubkeyIn, _ := os.Open("./test_keys/recipient_pub_key.b64")
	senderPrivKeyIn, _ := os.Open("./test_keys/sender_priv_key.b64")

	recipPubkeys, err := openpgp.ReadKeyRing(base64.NewDecoder(base64.StdEncoding, recipientPubkeyIn))
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}
	senderPrivkey, err := openpgp.ReadKeyRing(base64.NewDecoder(base64.StdEncoding, senderPrivKeyIn))
	if err != nil {
		t.Errorf("Problem with privkey: %v", err)
	}

	testMessage := bytes.NewBuffer([]byte(plaintextMessage))

	data, signature, err := EncryptAndSign(testMessage, recipPubkeys, senderPrivkey[0])
	if err != nil {
		t.Errorf("Problem with encryption: %v", err)
	}

	senderPubkeyIn, _ := os.Open("./test_keys/sender_pub_key.b64")

	senderPubkeys, err := openpgp.ReadKeyRing(base64.NewDecoder(base64.StdEncoding, senderPubkeyIn))
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}

	entity, err := openpgp.CheckDetachedSignature(senderPubkeys, base64.NewDecoder(base64.StdEncoding, strings.NewReader(data)), base64.NewDecoder(base64.StdEncoding, strings.NewReader(signature)))
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

	recipPrivKeyIn, _ := os.Open("./test_keys/recipient_priv_key.b64")

	recipPrivkey, err := openpgp.ReadKeyRing(base64.NewDecoder(base64.StdEncoding, recipPrivKeyIn))
	if err != nil {
		t.Errorf("Problem with pubkey: %v", err)
	}

	b64 := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	md, err := openpgp.ReadMessage(b64, recipPrivkey, nil, nil)
	if err != nil {
		t.Errorf("Error decrypting message: %v", err)
	}

	gz, err := gzip.NewReader(md.UnverifiedBody)
	if err != nil {
		t.Errorf("Error decompressing message: %v", err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(gz)
	decodedMessage := buf.String()

	if decodedMessage != plaintextMessage {
		t.Errorf("Error decrypting message. Expected: [%v], Got: [%v]", plaintextMessage, decodedMessage)
	}
}
