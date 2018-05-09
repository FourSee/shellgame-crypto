package main

import (
	_ "crypto/sha256"
	"fmt"
	"os"
	"shell_game_crypto_service/shell_crypto"

	_ "golang.org/x/crypto/ripemd160"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Goencrypt app
	app = kingpin.New("goencrypt", "A command line tool for encrypting files")

	// Generates new public and private keys
	keyGenCmd = app.Command("keygen", "Generates a new public/private key pair")
)

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	// generate keys
	case keyGenCmd.FullCommand():
		generateKeys()
	default:
		kingpin.FatalUsage("Unknown command")
	}
}

func generateKeys() {
	privKey, pubKey, err := shell_crypto.GenerateRSAKeyPair(2048)

	if err != nil {
		fmt.Printf("Error generating keys: %v", err)
		return
	}

	fmt.Println("Private key:")
	fmt.Printf("%v\r\n", string(privKey[:]))
	fmt.Println("Public key:")
	fmt.Printf("%v\r\n", string(pubKey[:]))
}
