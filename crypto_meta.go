package main

import (
	_ "crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SignatureType is the armor type for a PGP signature.
var SignatureType = "PGP SIGNATURE"

// MessageMetadata contains the result of parsing an OpenPGP encrypted and/or
// signed message.
type MessageMetadata struct {
	IsEncrypted              bool     // true if the message was encrypted.
	EncryptedToKeyIds        []uint64 // the list of recipient key ids.
	IsSymmetricallyEncrypted bool     // true if a passphrase could have decrypted the message.
	IsSigned                 bool     // true if the message is signed.
	SignedByKeyID            uint64   // the key id of the signer, if any.
	// If IsSigned is true and SignedBy is non-zero then the signature will
	// be verified as UnverifiedBody is read. The signature cannot be
	// checked until the whole of UnverifiedBody is read so UnverifiedBody
	// must be consumed until EOF before the data can be trusted. Even if a
	// message isn't signed (or the signer is unknown) the data may contain
	// an authentication code that is only checked once UnverifiedBody has
	// been consumed. Once EOF has been seen, the following fields are
	// valid. (An authentication code failure is reported as a
	// SignatureError error when reading from UnverifiedBody.)
	SignatureError error               // nil if the signature is good.
	Signature      *packet.Signature   // the signature packet itself, if v4 (default)
	SignatureV3    *packet.SignatureV3 // the signature packet if it is a v2 or v3 signature

}

// A keyEnvelopePair is used to store a private key with the envelope that
// contains a symmetric key, encrypted with that key.
type keyEnvelopePair struct {
	key          openpgp.Key
	encryptedKey *packet.EncryptedKey
}

// ReadMetadata parses an OpenPGP message that may be signed and/or encrypted.
// The given KeyRing should contain both public keys (for signature
// verification) and, possibly encrypted, private keys for decrypting.
// If config is nil, sensible defaults will be used.
func ReadMetadata(r io.Reader, config *packet.Config) (md *MessageMetadata, err error) {
	var p packet.Packet

	var symKeys []*packet.SymmetricKeyEncrypted

	packets := packet.NewReader(r)
	md = new(MessageMetadata)
	md.IsEncrypted = true

	// The message, if encrypted, starts with a number of packets
	// containing an encrypted decryption key. The decryption key is either
	// encrypted to a public key, or with a passphrase. This loop
	// collects these packets.
ParsePackets:
	for {
		p, err = packets.Next()
		if err != nil {
			return nil, err
		}
		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			// This packet contains the decryption key encrypted with a passphrase.
			md.IsSymmetricallyEncrypted = true
			symKeys = append(symKeys, p)
		case *packet.EncryptedKey:
			// This packet contains the decryption key encrypted to a public key.
			md.EncryptedToKeyIds = append(md.EncryptedToKeyIds, p.KeyId)
			switch p.Algo {
			case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoElGamal:
				break
			default:
				continue
			}
			// var keys []openpgp.Key
			// h := strings.ToUpper(fmt.Sprintf("%x", p.KeyId))
			// fmt.Println(h)
			// if p.KeyId == 0 {
			// 	keys = keyring.DecryptionKeys()
			// } else {
			// 	keys = keyring.KeysById(p.KeyId)
			// }
		case *packet.SymmetricallyEncrypted:
			// se = p
			break ParsePackets
		default:
			fmt.Println(p)
			// case *packet.Compressed, *packet.LiteralData, *packet.OnePassSignature:
			// 	// This message isn't encrypted.
			// 	if len(symKeys) != 0 || len(pubKeys) != 0 {
			// 		return nil, errors.StructuralError("key material not followed by encrypted message")
			// 	}
			// 	packets.Unread(p)
			// 	return readSignedMessage(packets, nil, keyring)
		}
	}

	return md, nil
}
