package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"compress/gzip"

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
	readFile()
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

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing private key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing private key: %s", err)
}

func decodePrivateKey(filename string) *packet.PrivateKey {

	// open ascii armored private key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PrivateKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid private key"), "Error parsing private key")
	}
	return key
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing public key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing public key: %s", err)
}

func decodePublicKey(filename string) *packet.PublicKey {

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
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid public key"), "Error parsing public key")
	}
	return key
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

func encryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	to := createEntityFromKeys(pubKey, privKey)

	w, err := armor.Encode(os.Stdout, "Message", make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)
	defer w.Close()

	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
	kingpin.FatalIfError(err, "Error creating entity for encryption")
	defer plain.Close()

	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	kingpin.FatalIfError(err, "Invalid compression level")

	n, err := io.Copy(compressed, os.Stdin)
	kingpin.FatalIfError(err, "Error writing encrypted file")
	kingpin.Errorf("Encrypted %d bytes", n)

	compressed.Close()
}

func readFile() {

	key := `-----BEGIN PGP MESSAGE-----
    
    hF4DQ5i5KRiiyH8SAQdAlDpqAVxqECsBxd5ockTTjHfZVoFyPxFg4czYcAusKEow
    lK3NZN5M3w522NAJ5fZQRY3tV9oT4V/iR4baxglYjtbrrmTPa27ZwyIAj8e9yM1o
    hQIMA7QNnpNS6SkhAQ//Z255xiTwNxfUgGoOD6H1qb+egeexelrzuz8P2ZQa1lLA
    NFsI+Tct7qGRs+Y0eum3FFJcm8rPhorCeatHC9EORnHiHCd/WFRlAEPsrVoBfGyn
    usjTL4KvsmvJcPginMW1u1i08Gq4Gdj30UmMuGZm70slHwshGNl1ItgC7PHE7k1a
    JcEkefQb3FrBSWncgFBTvJiUYuxeQRuZyBaNdNuWvM3LiV7BoYBcajcoU0rZpBgy
    RwSO7f7AdOQa7UabXRLn0m+p4Q44uoBrd/TfggBtw2Z6gA1csC57GvJfOHnBdX3D
    4PkjzAvPMbjlAqo7Cz6DoIHqen3FklemeOJFfCRImWmsNs2jk/LnnKWSr4v6+KB/
    onvDcXnojiSXC7XmdKX4fN/hE5ShBWfhsOzkAFvtSqjWzmIbbr5hI0DSx/fPUiYV
    e0vATUIAWvq8Yh+ub+7GWarkoAhYhHnSB6Ed7g5eeM8XjPkpmsRsJwgt+Wtw4+GW
    DQCk6BkYD+JviCPYkwPE2xsOEfPA95kgqf0z6Qb3vEmgGtgsgpkndMn3hnZ1ltXz
    fk5pvJv+/NRgyNA8d7KDKx0gKkhkO6uYHHlA20mYIyq0V/KgeAP2nwt+5kYe5sqq
    x5o9iYqaNNkD0i6/mSzRD9+IpXyR+XOBJe6/gzyXjD3ITQSCRi3aiunfR8+9w+vS
    swFY80SsLF37mKW6jYdRH3jwU08HyiRbm9A4JH6WWDgSgCIOYKlwYxz4Ulb7af0N
    GfiYF+50/XTqh2/VCoXX8a4yi8/rCn7yOo/G+Upcbfb0SaxuWDVAIDqjHOHOaGKR
    4daWj7zKBaU5fNPBPVcOxe6O1HZGNQkAxqlmPTi2MKxLyjSZpCVdtTh/MQK6aJ9P
    bzcG+QP918UThgN0yZx+8TFSueNGtQAcQPAwhUGCzCJcgWDL
    =4J4T
    -----END PGP MESSAGE-----`

	r := strings.NewReader(key)

	block, err := armor.Decode(r)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	var entityList openpgp.EntityList

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")
	fmt.Println(md.EncryptedToKeyIds)
}

func decryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	entity := createEntityFromKeys(pubKey, privKey)

	block, err := armor.Decode(os.Stdin)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	if block.Type != "Message" {
		kingpin.FatalIfError(err, "Invalid message type")
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	kingpin.FatalIfError(err, "Invalid compression level")
	defer compressed.Close()

	n, err := io.Copy(os.Stdout, compressed)
	kingpin.FatalIfError(err, "Error reading encrypted file")
	kingpin.Errorf("Decrypted %d bytes", n)
}

func signFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	signer := createEntityFromKeys(pubKey, privKey)

	err := openpgp.ArmoredDetachSign(os.Stdout, signer, os.Stdin, nil)
	kingpin.FatalIfError(err, "Error signing input")
}

func verifyFile() {
	pubKey := decodePublicKey(*publicKey)
	sig := decodeSignature(*signatureFile)

	hash := sig.Hash.New()
	io.Copy(hash, os.Stdin)

	err := pubKey.VerifySignature(hash, sig)
	kingpin.FatalIfError(err, "Error signing input")
	kingpin.Errorf("Verified signature")
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: *bits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func generateKeys() {
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

	priv, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".privkey"))
	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
	defer priv.Close()

	pub, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".pubkey"))
	kingpin.FatalIfError(err, "Error writing public key to file: %s", err)
	defer pub.Close()

	encodePrivateKey(priv, key)
	encodePublicKey(pub, key)
}
