package main

import (
	_ "crypto/sha256"

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
}
