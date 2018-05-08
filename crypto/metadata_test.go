package crypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/openpgp/armor"
)

func Benchmark_ReadMetadata(b *testing.B) {
	fileContents, _ := ioutil.ReadFile("./test_message.pgp")

	for n := 0; n < b.N; n++ {
		r := bytes.NewReader(fileContents)
		block, _ := armor.Decode(r)
		ReadRecipients(block.Body)
	}
}

func Test_ReadRecipients(t *testing.T) {
	r, _ := os.Open("./test_message.pgp")
	block, _ := armor.Decode(r)
	defer r.Close()

	md, err := ReadRecipients(block.Body)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	if md.IsEncrypted != true {
		t.Error("Should be encrypted, but wasn't")
	}

	expectedKeys := []string{"4398B92918A2C87F", "B40D9E9352E92921"}
	if !reflect.DeepEqual(md.EncryptedToKeyIds, expectedKeys) {
		t.Errorf("Expected recipient IDs: %v, got: %v", expectedKeys, md.EncryptedToKeyIds)
	}
}

func Benchmark_DecodePublicKey(b *testing.B) {
	fileContents, _ := ioutil.ReadFile("./test_key.asc")

	for n := 0; n < b.N; n++ {
		r := bytes.NewReader(fileContents)
		block, _ := armor.Decode(r)
		DecodePublicKey(block.Body)
	}
}

func Test_DecodePublicKey(t *testing.T) {
	r, _ := os.Open("./test_key.asc")
	defer r.Close()
	block, _ := armor.Decode(r)

	md, err := DecodePublicKey(block.Body)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	expectedPrimaryKeyID := "5E17A2717F2028B4"
	if md.PrimaryKeyID != expectedPrimaryKeyID {
		t.Errorf("Was expecting User ID %v, got %v", expectedPrimaryKeyID, md.PrimaryKeyID)
	}

	expectedKeys := []string{"6C73657F7E2E3E9C"}
	if !reflect.DeepEqual(md.SubKeyIDs, expectedKeys) {
		t.Errorf("Expected Subkey IDs: %v, got: %v", expectedKeys, md.SubKeyIDs)
	}
}
