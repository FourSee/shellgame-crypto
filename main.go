package main

import (
	_ "crypto/sha256"
	"os"

	_ "golang.org/x/crypto/ripemd160"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"shell_crypto"
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
	shell_crypto.GenerateRSAKeyPair(2048)
}
