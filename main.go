package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Goencrypt app
	app           = kingpin.New("goencrypt", "A command line tool for encrypting files")
	bits          = app.Flag("bits", "Bits for keys").Default("4096").Int()
	privateKey    = app.Flag("private", "Private key").String()
	publicKey     = app.Flag("public", "Public key").String()
	signatureFile = app.Flag("sig", "Signature File").String()

	// Generates new public and private keys
	keyGenCmd       = app.Command("keygen", "Generates a new public/private key pair")
	keyOutputPrefix = keyGenCmd.Arg("prefix", "Prefix of key files").Required().String()
	keyOutputDir    = keyGenCmd.Flag("d", "Output directory of key files").Default(".").String()

	// Encrypts a file with a public key
	encryptionCmd = app.Command("encrypt", "Encrypt from stdin")

	// Signs a file with a private key
	signCmd = app.Command("sign", "Sign stdin")

	// Verifies a file was signed with the public key
	verifyCmd = app.Command("verify", "Verify a signature of stdin")

	// Decrypts a file with a private key
	decryptionCmd = app.Command("decrypt", "Decrypt from stdin")

	// Reads an encrypted file to read metadata about it
	readCmd = app.Command("metadata", "Extracts metadata from an encrypted stdin")
)

func main() {
	readFile("./test_message.pgp")
	// switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	// // generate keys
	// case keyGenCmd.FullCommand():
	// 	generateKeys()
	// // case createEntityCmd.FullCommand():
	// // 	newEntity()
	// case encryptionCmd.FullCommand():
	// 	encryptFile()
	// case signCmd.FullCommand():
	// 	signFile()
	// case verifyCmd.FullCommand():
	// 	verifyFile()
	// case decryptionCmd.FullCommand():
	// 	decryptFile()
	// case readCmd.FullCommand():
	// 	readFile()
	// default:
	// 	readFile()
	// 	// kingpin.FatalUsage("Unknown command")
	// }
}

func decodeSignature(filename string) *packet.Signature {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.SignatureType {
		kingpin.FatalIfError(errors.New("Invalid signature file"), "Error decoding signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading signature")

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid signature"), "Error parsing signature")
	}
	return sig
}

func decodePublicKey(filename string) (key KeyIDs) {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PublicKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}
	reader := packet.NewReader(block.Body)

	// key, ok := pkt.(*packet.PublicKey)
	// hKey := strings.ToUpper(fmt.Sprintf("%x", key.KeyId))
	// fmt.Println(hKey)
ParsePackets:
	for {
		pkt, err := reader.Next()
		if err != nil {
			break ParsePackets
		}
		switch p := pkt.(type) {
		case *packet.PublicKey:
			hexKey := strings.ToUpper(fmt.Sprintf("%x", p.KeyId))
			if p.IsSubkey {
				key.SubKeyIDs = append(key.SubKeyIDs, hexKey)
			} else {
				key.PrimaryKeyID = hexKey
			}
		case *packet.UserId:
			key.UserID = *p
		default:
			continue
		}

	}
	return key
}

func readFile(filename string) (md *MessageMetadata, err error) {

	// key :=
	// r := bytes.NewReader(key)
	r, err := os.Open(filename)
	block, err := armor.Decode(r)
	// kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)
	// var entityList openpgp.EntityList
	// md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	md, err = ReadMetadata(block.Body, nil)
	// kingpin.FatalIfError(err, "Error reading message")
	// fmt.Printf("%v", md.EncryptedToKeyIds)
	// fmt.Println(md.EncryptedToKeyIds)
	return md, err
}
