package ffi

/*
#include "signal_c_binding.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"signalexample/transport"
)

func BundleToPayload(bundle *C.SignalGoPreKeyBundle) (*transport.BundlePayload, error) {
	if bundle == nil {
		return nil, errors.New("bundle pointer is nil")
	}

	var payload transport.BundlePayload

	var regID C.uint32_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_registration_id(bundle, &regID), "get_registration_id"); err != nil {
		return nil, err
	}
	payload.RegistrationID = uint32(regID)

	var deviceID C.uint32_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_device_id(bundle, &deviceID), "get_device_id"); err != nil {
		return nil, err
	}
	payload.DeviceID = uint32(deviceID)

	var hasPreKey C.bool
	var preKeyID C.uint32_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_prekey_id(bundle, &hasPreKey, &preKeyID), "get_prekey_id"); err != nil {
		return nil, err
	}

	var preKeyPtr *C.uint8_t
	var preKeyLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_prekey_public(bundle, &preKeyPtr, &preKeyLen), "get_prekey_public"); err != nil {
		return nil, err
	}
	if bool(hasPreKey) {
		payload.PreKey = &transport.PreKeyEnvelope{
			ID:     uint32(preKeyID),
			Public: copyAndFree(preKeyPtr, preKeyLen),
		}
	} else {
		if preKeyPtr != nil {
			C.signalgo_buffer_free(preKeyPtr, preKeyLen)
		}
	}

	var signedID C.uint32_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_signed_prekey_id(bundle, &signedID), "get_signed_prekey_id"); err != nil {
		return nil, err
	}

	var signedPtr *C.uint8_t
	var signedLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_signed_prekey_public(bundle, &signedPtr, &signedLen), "get_signed_prekey_public"); err != nil {
		return nil, err
	}
	signedPublic := copyAndFree(signedPtr, signedLen)

	var signedSigPtr *C.uint8_t
	var signedSigLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_signed_prekey_signature(bundle, &signedSigPtr, &signedSigLen), "get_signed_prekey_signature"); err != nil {
		return nil, err
	}
	signedSignature := copyAndFree(signedSigPtr, signedSigLen)

	payload.SignedPreKey = transport.SignedPreKeyEnvelope{
		ID:        uint32(signedID),
		Public:    signedPublic,
		Signature: signedSignature,
	}

	var identityPtr *C.uint8_t
	var identityLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_identity_key(bundle, &identityPtr, &identityLen), "get_identity_key"); err != nil {
		return nil, err
	}
	payload.IdentityKey = copyAndFree(identityPtr, identityLen)

	var kyberID C.uint32_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_kyber_prekey_id(bundle, &kyberID), "get_kyber_prekey_id"); err != nil {
		return nil, err
	}

	var kyberPtr *C.uint8_t
	var kyberLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_kyber_prekey_public(bundle, &kyberPtr, &kyberLen), "get_kyber_prekey_public"); err != nil {
		return nil, err
	}
	kyberPublic := copyAndFree(kyberPtr, kyberLen)

	var kyberSigPtr *C.uint8_t
	var kyberSigLen C.size_t
	if err := ffiCode(C.signalgo_prekey_bundle_get_kyber_prekey_signature(bundle, &kyberSigPtr, &kyberSigLen), "get_kyber_prekey_signature"); err != nil {
		return nil, err
	}
	kyberSignature := copyAndFree(kyberSigPtr, kyberSigLen)

	payload.KyberPreKey = transport.KyberPreKeyEnvelope{
		ID:        uint32(kyberID),
		Public:    kyberPublic,
		Signature: kyberSignature,
	}

	return &payload, nil
}

func BundleFromPayload(payload *transport.BundlePayload) (*C.SignalGoPreKeyBundle, error) {
	if payload == nil {
		return nil, errors.New("payload is nil")
	}
	if len(payload.IdentityKey) == 0 {
		return nil, errors.New("identity key is required")
	}
	if len(payload.SignedPreKey.Public) == 0 || len(payload.SignedPreKey.Signature) == 0 {
		return nil, errors.New("signed pre-key is incomplete")
	}
	if len(payload.KyberPreKey.Public) == 0 || len(payload.KyberPreKey.Signature) == 0 {
		return nil, errors.New("kyber pre-key is incomplete")
	}

	hasPreKey := C.bool(false)
	var preKeyID C.uint32_t
	var preKeyPtr *C.uint8_t
	var preKeyLen C.size_t
	if payload.PreKey != nil {
		if len(payload.PreKey.Public) == 0 {
			return nil, errors.New("pre-key public is empty")
		}
		hasPreKey = C.bool(true)
		preKeyID = C.uint32_t(payload.PreKey.ID)
		preKeyLen = C.size_t(len(payload.PreKey.Public))
		preKeyPtr = (*C.uint8_t)(unsafe.Pointer(&payload.PreKey.Public[0]))
	}

	signedPublic := (*C.uint8_t)(unsafe.Pointer(&payload.SignedPreKey.Public[0]))
	signedSignature := (*C.uint8_t)(unsafe.Pointer(&payload.SignedPreKey.Signature[0]))
	identityPtr := (*C.uint8_t)(unsafe.Pointer(&payload.IdentityKey[0]))
	kyberPublic := (*C.uint8_t)(unsafe.Pointer(&payload.KyberPreKey.Public[0]))
	kyberSignature := (*C.uint8_t)(unsafe.Pointer(&payload.KyberPreKey.Signature[0]))

	var out *C.SignalGoPreKeyBundle
	rc := C.signalgo_prekey_bundle_from_parts(
		C.uint32_t(payload.RegistrationID),
		C.uint32_t(payload.DeviceID),
		hasPreKey,
		preKeyID,
		preKeyPtr,
		preKeyLen,
		C.uint32_t(payload.SignedPreKey.ID),
		signedPublic,
		C.size_t(len(payload.SignedPreKey.Public)),
		signedSignature,
		C.size_t(len(payload.SignedPreKey.Signature)),
		identityPtr,
		C.size_t(len(payload.IdentityKey)),
		C.uint32_t(payload.KyberPreKey.ID),
		kyberPublic,
		C.size_t(len(payload.KyberPreKey.Public)),
		kyberSignature,
		C.size_t(len(payload.KyberPreKey.Signature)),
		&out,
	)
	if err := ffiCode(rc, "prekey_bundle_from_parts"); err != nil {
		return nil, err
	}
	return out, nil
}
