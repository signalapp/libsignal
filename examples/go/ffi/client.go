package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../signal-c-binding/include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lsignal_c_binding -ldl -lpthread -lm
#include <stdlib.h>
#include "signal_c_binding.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

const (
	CiphertextTypeUnknown     = 0
	CiphertextTypeKeyExchange = 1
	CiphertextTypeWhisper     = 2
	CiphertextTypePreKey      = 3
)

func ffiCode(rc C.int32_t, action string) error {
	if rc != 0 {
		return fmt.Errorf("%s: signal ffi returned %d", action, int(rc))
	}
	return nil
}

type Client struct {
	Name  string
	store *C.SignalGoProtocolStore
}

type Address = *C.SignalGoProtocolAddress
type CiphertextMessage = *C.SignalGoCiphertextMessage
type SignalMessage = *C.SignalGoSignalMessage
type PreKeySignalMessage = *C.SignalGoPreKeySignalMessage
type PreKeyBundle = *C.SignalGoPreKeyBundle

func NewClient(name string, registrationID, deviceID uint32) (*Client, error) {
	identity := C.signalgo_identity_keypair_generate()
	if identity == nil {
		return nil, fmt.Errorf("%s: failed to generate identity key pair", name)
	}
	defer C.signalgo_identity_keypair_free(identity)

	store := C.signalgo_protocol_store_new(identity, C.uint32_t(registrationID))
	if store == nil {
		return nil, fmt.Errorf("%s: failed to create protocol store", name)
	}

	c := &Client{Name: name, store: store}
	runtime.SetFinalizer(c, (*Client).Close)
	return c, nil
}

func (c *Client) Close() {
	if c.store != nil {
		C.signalgo_protocol_store_free(c.store)
		c.store = nil
	}
}

func (c *Client) GeneratePreKeyBundle(registrationID, deviceID, preKeyID, signedPreKeyID, kyberPreKeyID uint32) (*C.SignalGoPreKeyBundle, error) {
	var bundle *C.SignalGoPreKeyBundle
	rc := C.signalgo_store_generate_prekey_bundle(
		c.store,
		C.uint32_t(registrationID),
		C.uint32_t(deviceID),
		C.uint32_t(preKeyID),
		C.uint32_t(signedPreKeyID),
		C.uint32_t(kyberPreKeyID),
		(**C.SignalGoPreKeyBundle)(unsafe.Pointer(&bundle)),
	)
	if rc != 0 || bundle == nil {
		return nil, fmt.Errorf("%s: failed to generate pre-key bundle (code %d)", c.Name, int(rc))
	}
	return bundle, nil
}

func (c *Client) ProcessPreKeyBundle(remote *C.SignalGoProtocolAddress, bundle *C.SignalGoPreKeyBundle) error {
	now := time.Now().UnixMilli()
	rc := C.signalgo_store_process_prekey_bundle(
		c.store,
		remote,
		bundle,
		C.uint64_t(now),
		C.bool(true),
	)
	if rc != 0 {
		return fmt.Errorf("%s: process_prekey_bundle failed with code %d", c.Name, int(rc))
	}
	return nil
}

func (c *Client) Encrypt(remote *C.SignalGoProtocolAddress, plaintext []byte) (*C.SignalGoCiphertextMessage, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%s: plaintext is empty", c.Name)
	}
	var message *C.SignalGoCiphertextMessage
	rc := C.signalgo_store_encrypt_message(
		c.store,
		remote,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])),
		C.size_t(len(plaintext)),
		C.uint64_t(time.Now().UnixMilli()),
		(**C.SignalGoCiphertextMessage)(unsafe.Pointer(&message)),
	)
	if rc != 0 || message == nil {
		return nil, fmt.Errorf("%s: encrypt failed with code %d", c.Name, int(rc))
	}
	return message, nil
}

func (c *Client) DecryptSignal(remote *C.SignalGoProtocolAddress, msg *C.SignalGoSignalMessage) ([]byte, error) {
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.signalgo_store_decrypt_signal_message(
		c.store,
		remote,
		msg,
		(**C.uint8_t)(unsafe.Pointer(&outPtr)),
		(*C.size_t)(unsafe.Pointer(&outLen)),
	)
	if rc != 0 {
		return nil, fmt.Errorf("%s: decrypt_signal failed with code %d", c.Name, int(rc))
	}
	return copyAndFree(outPtr, outLen), nil
}

func (c *Client) DecryptPreKey(remote *C.SignalGoProtocolAddress, msg *C.SignalGoPreKeySignalMessage) ([]byte, error) {
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.signalgo_store_decrypt_prekey_message(
		c.store,
		remote,
		msg,
		C.bool(true),
		(**C.uint8_t)(unsafe.Pointer(&outPtr)),
		(*C.size_t)(unsafe.Pointer(&outLen)),
	)
	if rc != 0 {
		return nil, fmt.Errorf("%s: decrypt_prekey failed with code %d", c.Name, int(rc))
	}
	return copyAndFree(outPtr, outLen), nil
}

func CiphertextType(msg *C.SignalGoCiphertextMessage) uint8 {
	return uint8(C.signalgo_ciphertext_message_get_type(msg))
}

func CiphertextBytes(msg *C.SignalGoCiphertextMessage) []byte {
	var outLen C.size_t
	data := C.signalgo_ciphertext_message_serialize(msg, &outLen)
	return copyAndFree(data, outLen)
}

func SignalMessageFromBytes(payload []byte) (*C.SignalGoSignalMessage, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("signal message payload empty")
	}
	msg := C.signalgo_signal_message_from_bytes((*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))
	if msg == nil {
		return nil, fmt.Errorf("failed to parse signal message")
	}
	return msg, nil
}

func PreKeySignalMessageFromBytes(payload []byte) (*C.SignalGoPreKeySignalMessage, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("pre-key message payload empty")
	}
	msg := C.signalgo_prekey_signal_message_from_bytes((*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))
	if msg == nil {
		return nil, fmt.Errorf("failed to parse pre-key signal message")
	}
	return msg, nil
}

func FreeCiphertext(msg *C.SignalGoCiphertextMessage) {
	if msg != nil {
		C.signalgo_ciphertext_message_free(msg)
	}
}

func FreeSignalMessage(msg *C.SignalGoSignalMessage) {
	if msg != nil {
		C.signalgo_signal_message_free(msg)
	}
}

func FreePreKeySignalMessage(msg *C.SignalGoPreKeySignalMessage) {
	if msg != nil {
		C.signalgo_prekey_signal_message_free(msg)
	}
}

func FreePreKeyBundle(bundle *C.SignalGoPreKeyBundle) {
	if bundle != nil {
		C.signalgo_prekey_bundle_free(bundle)
	}
}

func NewAddress(name string, deviceID uint32) (*C.SignalGoProtocolAddress, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	addr := C.signalgo_protocol_address_new(cName, C.uint32_t(deviceID))
	if addr == nil {
		return nil, fmt.Errorf("failed to create protocol address")
	}
	return addr, nil
}

func FreeAddress(addr *C.SignalGoProtocolAddress) {
	if addr != nil {
		C.signalgo_protocol_address_free(addr)
	}
}

func copyAndFree(ptr *C.uint8_t, length C.size_t) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	goBytes := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	C.signalgo_buffer_free(ptr, length)
	return goBytes
}
