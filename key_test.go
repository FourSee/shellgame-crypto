package shellgamecrypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func Benchmark_DecodePublicKey(b *testing.B) {
	fileContents, _ := ioutil.ReadFile("./test_pub_key.asc")

	for n := 0; n < b.N; n++ {
		r := bytes.NewReader(fileContents)
		block, _ := armor.Decode(r)
		DecodePublicKey(block.Body)
	}
}

func Test_DecodePublicKey(t *testing.T) {
	r, _ := os.Open("./test_pub_key.asc")
	defer r.Close()
	block, _ := armor.Decode(r)

	md, err := DecodePublicKey(block.Body)

	if err != nil {
		t.Errorf("Error decoding message: %v", err)
	}

	expectedPrimaryKeyID := "2604AFED5E51266C"
	if md.PrimaryKeyID != expectedPrimaryKeyID {
		t.Errorf("Was expecting User ID %v, got %v", expectedPrimaryKeyID, md.PrimaryKeyID)
	}

	expectedKeys := []string{"F6B4A2643CD1CF0C"}
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

	_, err = openpgp.ReadArmoredKeyRing(bytes.NewBuffer([]byte(pubKey)))
	if err != nil {
		t.Errorf("Problem with public key: %v", err)
	}

	_, err = openpgp.ReadArmoredKeyRing(bytes.NewBuffer([]byte(privKey)))
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
