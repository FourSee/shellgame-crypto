package shellgamecrypto

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Benchmark_ReadMetadata(b *testing.B) {
	fileContents, _ := ioutil.ReadFile("./test_message.pgp")

	for n := 0; n < b.N; n++ {
		r := bytes.NewReader(fileContents)
		block := base64.NewDecoder(base64.StdEncoding, r)
		ReadRecipients(block)
	}
}

func Test_ReadRecipients(t *testing.T) {
	r, _ := os.Open("./test_message.pgp")
	block := base64.NewDecoder(base64.StdEncoding, r)
	defer r.Close()

	md, err := ReadRecipients(block)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	if !md.IsEncrypted {
		t.Error("Should be encrypted, but wasn't")
	}

	expectedKeys := []string{"6A7383DC331DA728"}
	if !reflect.DeepEqual(md.EncryptedToKeyIds, expectedKeys) {
		t.Errorf("Expected recipient IDs: %v, got: %v", expectedKeys, md.EncryptedToKeyIds)
	}
}

func Test_ReadSigner(t *testing.T) {
	r, _ := os.Open("./test_message.pgp.sig")
	block := base64.NewDecoder(base64.StdEncoding, r)
	defer r.Close()

	_, err := ReadSigner(block)

	if err != nil {
		t.Errorf("Error decoding signature: %v", err)
	}
}
