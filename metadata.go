package shellgamecrypto

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// MessageMetadata contains the result of parsing an OpenPGP encrypted and/or
// signed message.
type MessageMetadata struct {
	IsEncrypted              bool     // true if the message was encrypted.
	EncryptedToKeyIds        []string // the list of recipient key ids.
	IsSymmetricallyEncrypted bool     // true if a passphrase could have decrypted the message.
	IsSigned                 bool     // true if the message is signed.
	SignedByKeyID            string   // the key id of the signer, if any.
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

// KeyIDs is the public key metadata container
type KeyIDs struct {
	PrimaryKeyID string
	SubKeyIDs    []string
	UserID       packet.UserId
}

// EntityKeyIDs extracts the key IDs from a given entity
func EntityKeyIDs(entity *openpgp.Entity) (keys KeyIDs, err error) {
	keys.PrimaryKeyID = strings.ToUpper(fmt.Sprintf("%x", entity.PrimaryKey.KeyId))
	for _, subkey := range entity.Subkeys {
		keys.SubKeyIDs = append(keys.SubKeyIDs, strings.ToUpper(fmt.Sprintf("%x", subkey.PublicKey.KeyId)))
	}
	return
}

// ReadRecipients parses an OpenPGP message that may be signed and/or encrypted.
// An encrypted & signed message cannot be signature-validated without the decryption key
func ReadRecipients(r io.Reader) (md *MessageMetadata, err error) {
	var p packet.Packet

	packets := packet.NewReader(r)
	md = new(MessageMetadata)
	md.IsEncrypted = true
ParsePackets:
	for {
		p, err = packets.Next()
		if err != nil {
			return md, err
		}
		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			// This packet contains the decryption key encrypted with a passphrase.
			md.IsSymmetricallyEncrypted = true
		case *packet.EncryptedKey:
			// This packet contains the decryption key encrypted to a public key.
			md.EncryptedToKeyIds = append(md.EncryptedToKeyIds, strings.ToUpper(fmt.Sprintf("%x", p.KeyId)))
		// This *should* be the final packet in a stream
		case *packet.SymmetricallyEncrypted:
			break ParsePackets
		}
	}
	return md, nil
}

// ReadSigner returns the long key ID of whoever signed the message
func ReadSigner(r io.Reader) (keyID string, err error) {
	var p packet.Packet

	packets := packet.NewReader(r)
	for {
		p, _ = packets.Next()
		if err != nil {
			return
		}
		switch p := p.(type) {
		case *packet.Signature:
			keyID = strings.ToUpper(fmt.Sprintf("%x", *p.IssuerKeyId))
			return keyID, nil
		default:
			if p == nil {
				return
			}
		}
	}
}
