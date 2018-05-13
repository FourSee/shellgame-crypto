package shellgamecrypto

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func Benchmark_DecodePublicKey(b *testing.B) {
	fileContents, _ := ioutil.ReadFile("./test_pub_key.b64")

	for n := 0; n < b.N; n++ {
		r := bytes.NewReader(fileContents)
		decoder := base64.NewDecoder(base64.StdEncoding, r)
		DecodePublicKey(decoder)
	}
}

func Test_DecodePublicKey(t *testing.T) {
	r, _ := os.Open("./test_keys/sender_pub_key.b64")

	defer r.Close()
	decoder := base64.NewDecoder(base64.StdEncoding, r)

	md, err := DecodePublicKey(decoder)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	expectedPrimaryKeyID := "E35BD19357C4033E"
	if md.PrimaryKeyID != expectedPrimaryKeyID {
		t.Errorf("Was expecting User ID %v, got %v", expectedPrimaryKeyID, md.PrimaryKeyID)
	}

	expectedKeys := []string{"6A7383DC331DA728"}
	if !reflect.DeepEqual(md.SubKeyIDs, expectedKeys) {
		t.Errorf("Expected Subkey IDs: %v, got: %v", expectedKeys, md.SubKeyIDs)
	}
}

func Test_GenerateKey(t *testing.T) {

	// In practice, we'll want to use system usernames, hostnames, etc
	// user, err := user.Current()
	// hostname, _ := os.Hostname()
	// user.Username, "test key", fmt.Sprintf("%v@%v", user.Username, hostname)

	name := "Test key user"
	comment := "Generated programatically as a test"
	email := "test.user@example.org"
	privKey, pubKey, err := GenerateRSAKeyPair(2048, name, comment, email)

	if err != nil {
		t.Errorf("Error generating a 2048-bit RSA key, got: %v", err)
	}
	pubDecoder := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer([]byte(pubKey)))
	_, err = openpgp.ReadKeyRing(pubDecoder)
	// _, err = openpgp.pubDecoder()
	if err != nil {
		t.Errorf("Problem with public key: %v", err)
	}

	privDecoder := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer([]byte(privKey)))
	_, err = openpgp.ReadKeyRing(privDecoder)
	if err != nil {
		t.Errorf("Problem with private key: %v", err)
	}
}

func Benchmark_Generate2048BitKey(b *testing.B) {
	name := "Test key user"
	comment := "Generated programatically as a test"
	email := "test.user@example.org"

	for n := 0; n < b.N; n++ {
		_, _, err := GenerateRSAKeyPair(2048, name, comment, email)
		if err != nil {
			b.Errorf("Expected nil error generating a 2048-bit RSA key, got: %v", err)
		}
	}
}

// A 4096-bit RSA key takes ~11x longer to generate than a 2048-bit
func Benchmark_Generate4096BitKey(b *testing.B) {
	name := "Test key user"
	comment := "Generated programatically as a test"
	email := "test.user@example.org"

	for n := 0; n < b.N; n++ {
		_, _, err := GenerateRSAKeyPair(4096, name, comment, email)
		if err != nil {
			b.Errorf("Expected nil error generating a 4096-bit RSA key, got: %v", err)
		}
	}
}
