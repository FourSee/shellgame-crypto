package main

import (
	"testing"
)

func BenchmarkReadFile(b *testing.B) {
	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		readFile()
		// fmt.Printf("%v", md.EncryptedToKeyIds)
	}
}
