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
		ReadMetadata(block.Body, nil)
	}
}

func Test_ReadMetadata(t *testing.T) {
	r, _ := os.Open("./test_message.pgp")
	block, _ := armor.Decode(r)
	defer r.Close()

	md, err := ReadMetadata(block.Body, nil)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	if md.IsEncrypted != true {
		t.Error("Should be encrypted, but wasn't")
	}

	if md.IsSigned != true {
		t.Error("Should be signed, but wasn't")
	}

	expectedKeys := []string{"B40D9E9352E92921", "6C73657F7E2E3E9C"}
	if !reflect.DeepEqual(md.EncryptedToKeyIds, expectedKeys) {
		t.Errorf("Expected recipient IDs: %v, got: %v", expectedKeys, md.EncryptedToKeyIds)
	}
}
