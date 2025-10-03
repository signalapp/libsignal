package main

import (
	"fmt"
	"log"

	"signalexample/ffi"
)

func main() {
	alice, err := ffi.NewClient("alice", 2024, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()

	bob, err := ffi.NewClient("bob", 2024, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	charlie, err := ffi.NewClient("charlie", 2024, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer charlie.Close()

	aliceAddr, err := ffi.NewAddress("alice", 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreeAddress(aliceAddr)

	bobAddr, err := ffi.NewAddress("bob", 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreeAddress(bobAddr)

	charlieAddr, err := ffi.NewAddress("charlie", 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreeAddress(charlieAddr)

	bobBundle, err := bob.GeneratePreKeyBundle(2024, 1, 1, 1, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreePreKeyBundle(bobBundle)

	charlieBundle, err := charlie.GeneratePreKeyBundle(2024, 1, 1, 1, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreePreKeyBundle(charlieBundle)

	if err := alice.ProcessPreKeyBundle(bobAddr, charlieBundle); err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("Hello from Naveen via Signal Protocol!")
	ciphertext, err := alice.Encrypt(bobAddr, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	defer ffi.FreeCiphertext(ciphertext)

	ctype := ffi.CiphertextType(ciphertext)
	payload := ffi.CiphertextBytes(ciphertext)
	fmt.Printf("Ciphertext type=%d size=%d\n", ctype, len(payload))

	if len(payload) == 0 {
		log.Fatal("empty ciphertext payload")
	}

	var decrypted []byte
	switch ctype {
	case ffi.CiphertextTypePreKey:
		pk, err := ffi.PreKeySignalMessageFromBytes(payload)
		if err != nil {
			log.Fatal(err)
		}
		defer ffi.FreePreKeySignalMessage(pk)

		decrypted, err = charlie.DecryptPreKey(aliceAddr, pk)
		if err != nil {
			log.Fatal(err)
		}
	case ffi.CiphertextTypeWhisper:
		sig, err := ffi.SignalMessageFromBytes(payload)
		if err != nil {
			log.Fatal(err)
		}
		defer ffi.FreeSignalMessage(sig)

		decrypted, err = bob.DecryptSignal(aliceAddr, sig)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unexpected ciphertext type %d", ctype)
	}

	fmt.Printf("Bob decrypted: %s\n", string(decrypted))
}
