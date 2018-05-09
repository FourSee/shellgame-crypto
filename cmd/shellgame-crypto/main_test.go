package main

import (
	"testing"
)

func BenchmarkReadFile(b *testing.B) {
	for n := 0; n < b.N; n++ {
		readFile("./test_message.pgp")
	}
}

func BenchmarkDecodeSignature(b *testing.B) {

	for n := 0; n < b.N; n++ {
		// pubKey := decodePublicKey("./test_signature.asc")
		// r, _ := os.Open("./test_message.pgp")
		// block, _ := armor.Decode(r)

		// entity := createEntityFromKeys(pubKey, nil)

		// var entityList openpgp.EntityList
		// entityList = append(entityList, entity)

		// md, err := readFile()
		// md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
		decodePublicKey("./test_signature.asc")
		// b, err := json.Marshal(key)
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		// fmt.Println(string(b))
		// fmt.Printf("Primary key: %v \n", key.PrimaryKeyID)
		// fmt.Printf("Subkeys: %v \n", key.SubKeyIDs)
		// fmt.Printf("User info: %v \n", key.UserID)
	}
}
