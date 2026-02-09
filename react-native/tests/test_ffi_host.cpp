//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Host-side integration test for libsignal FFI bindings.
// This test links against the host-compiled libsignal_ffi shared library
// and verifies that FFI function calls work correctly.
//

#include <cstdio>
#include <cstring>
#include <cassert>
#include <cstdlib>
#include <vector>

extern "C" {
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wtypedef-redefinition"
#endif
#include "signal_ffi_cpp.h"
#pragma GCC diagnostic pop
}

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  TEST %-50s ", #name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        printf("[FAIL] %s\n", msg); \
    } while (0)

// Helper to convert MutPointer -> ConstPointer by casting the raw field
template<typename ConstT, typename MutT>
ConstT as_const(const MutT& mut) {
    ConstT c;
    c.raw = reinterpret_cast<const typename std::remove_pointer<decltype(c.raw)>::type*>(mut.raw);
    return c;
}

// Test 1: Private key generation and serialization
void test_private_key_generate() {
    TEST(PrivateKey_Generate);

    SignalMutPointerPrivateKey key = {nullptr};
    SignalFfiError* err = signal_privatekey_generate(&key);
    if (err) { FAIL("generate failed"); signal_error_free(err); return; }
    if (!key.raw) { FAIL("key is null"); return; }

    SignalOwnedBuffer buf = {nullptr, 0};
    err = signal_privatekey_serialize(&buf, as_const<SignalConstPointerPrivateKey>(key));
    if (err) { FAIL("serialize failed"); signal_error_free(err); signal_privatekey_destroy(key); return; }
    if (buf.length != 32) {
        char msg[64]; snprintf(msg, sizeof(msg), "expected 32 bytes, got %zu", buf.length);
        FAIL(msg); signal_free_buffer(buf.base, buf.length); signal_privatekey_destroy(key); return;
    }

    signal_free_buffer(buf.base, buf.length);
    signal_privatekey_destroy(key);
    PASS();
}

// Test 2: Public key from private key
void test_public_key_from_private() {
    TEST(PublicKey_FromPrivate);

    SignalMutPointerPrivateKey privKey = {nullptr};
    SignalMutPointerPublicKey pubKey = {nullptr};
    SignalOwnedBuffer buf = {nullptr, 0};

    SignalFfiError* err = signal_privatekey_generate(&privKey);
    if (err) { FAIL("generate failed"); signal_error_free(err); return; }

    err = signal_privatekey_get_public_key(&pubKey, as_const<SignalConstPointerPrivateKey>(privKey));
    if (err) { FAIL("get_public_key failed"); signal_error_free(err); signal_privatekey_destroy(privKey); return; }

    err = signal_publickey_serialize(&buf, as_const<SignalConstPointerPublicKey>(pubKey));
    if (err) { FAIL("serialize failed"); signal_error_free(err); signal_publickey_destroy(pubKey); signal_privatekey_destroy(privKey); return; }

    if (buf.length != 33) {
        char msg[64]; snprintf(msg, sizeof(msg), "expected 33 bytes, got %zu", buf.length);
        FAIL(msg);
    } else {
        PASS();
    }

    signal_free_buffer(buf.base, buf.length);
    signal_publickey_destroy(pubKey);
    signal_privatekey_destroy(privKey);
}

// Test 3: Public key round-trip (serialize → deserialize → serialize)
void test_public_key_roundtrip() {
    TEST(PublicKey_Roundtrip);

    SignalMutPointerPrivateKey privKey = {nullptr};
    SignalMutPointerPublicKey pubKey = {nullptr};
    SignalOwnedBuffer serialized = {nullptr, 0};
    SignalMutPointerPublicKey deserialized = {nullptr};
    SignalOwnedBuffer reserialized = {nullptr, 0};
    bool ok = false;

    SignalFfiError* err = signal_privatekey_generate(&privKey);
    if (err) { FAIL("generate"); signal_error_free(err); return; }

    err = signal_privatekey_get_public_key(&pubKey, as_const<SignalConstPointerPrivateKey>(privKey));
    if (err) { FAIL("get_public_key"); signal_error_free(err); goto done; }

    err = signal_publickey_serialize(&serialized, as_const<SignalConstPointerPublicKey>(pubKey));
    if (err) { FAIL("serialize"); signal_error_free(err); goto done; }

    {
        SignalBorrowedBuffer borrowed = {serialized.base, serialized.length};
        err = signal_publickey_deserialize(&deserialized, borrowed);
        if (err) { FAIL("deserialize"); signal_error_free(err); goto done; }
    }

    err = signal_publickey_serialize(&reserialized, as_const<SignalConstPointerPublicKey>(deserialized));
    if (err) { FAIL("reserialize"); signal_error_free(err); goto done; }

    if (serialized.length != reserialized.length ||
        memcmp(serialized.base, reserialized.base, serialized.length) != 0) {
        FAIL("round-trip mismatch");
    } else {
        ok = true;
        PASS();
    }

done:
    if (reserialized.base) signal_free_buffer(reserialized.base, reserialized.length);
    if (serialized.base) signal_free_buffer(serialized.base, serialized.length);
    if (deserialized.raw) signal_publickey_destroy(deserialized);
    signal_publickey_destroy(pubKey);
    signal_privatekey_destroy(privKey);
}

// Test 4: ECDH key agreement
void test_ecdh_agreement() {
    TEST(ECDH_Agreement);

    SignalMutPointerPrivateKey alice_priv = {nullptr}, bob_priv = {nullptr};
    SignalMutPointerPublicKey alice_pub = {nullptr}, bob_pub = {nullptr};
    SignalOwnedBuffer shared1 = {nullptr, 0}, shared2 = {nullptr, 0};

    SignalFfiError* err = signal_privatekey_generate(&alice_priv);
    if (err) { FAIL("alice generate"); signal_error_free(err); return; }
    err = signal_privatekey_generate(&bob_priv);
    if (err) { FAIL("bob generate"); signal_error_free(err); signal_privatekey_destroy(alice_priv); return; }

    err = signal_privatekey_get_public_key(&alice_pub, as_const<SignalConstPointerPrivateKey>(alice_priv));
    if (err) { FAIL("alice pub"); signal_error_free(err); goto done; }
    err = signal_privatekey_get_public_key(&bob_pub, as_const<SignalConstPointerPrivateKey>(bob_priv));
    if (err) { FAIL("bob pub"); signal_error_free(err); goto done; }

    err = signal_privatekey_agree(&shared1,
        as_const<SignalConstPointerPrivateKey>(alice_priv),
        as_const<SignalConstPointerPublicKey>(bob_pub));
    if (err) { FAIL("alice agree"); signal_error_free(err); goto done; }

    err = signal_privatekey_agree(&shared2,
        as_const<SignalConstPointerPrivateKey>(bob_priv),
        as_const<SignalConstPointerPublicKey>(alice_pub));
    if (err) { FAIL("bob agree"); signal_error_free(err); goto done; }

    if (shared1.length != 32 || shared2.length != 32) {
        FAIL("wrong size");
    } else if (memcmp(shared1.base, shared2.base, 32) != 0) {
        FAIL("secrets don't match");
    } else {
        PASS();
    }

done:
    if (shared1.base) signal_free_buffer(shared1.base, shared1.length);
    if (shared2.base) signal_free_buffer(shared2.base, shared2.length);
    signal_publickey_destroy(alice_pub);
    signal_publickey_destroy(bob_pub);
    signal_privatekey_destroy(alice_priv);
    signal_privatekey_destroy(bob_priv);
}

// Test 5: Protocol address
void test_protocol_address() {
    TEST(ProtocolAddress);

    SignalMutPointerProtocolAddress addr = {nullptr};
    const char* name = nullptr;
    uint32_t device_id = 0;

    SignalFfiError* err = signal_address_new(&addr, "+14155550100", 1);
    if (err) { FAIL("new"); signal_error_free(err); return; }

    err = signal_address_get_name(&name, as_const<SignalConstPointerProtocolAddress>(addr));
    if (err) { FAIL("get_name"); signal_error_free(err); goto done; }
    if (strcmp(name, "+14155550100") != 0) {
        FAIL("name mismatch"); signal_free_string(name); goto done;
    }
    signal_free_string(name);
    name = nullptr;

    err = signal_address_get_device_id(&device_id, as_const<SignalConstPointerProtocolAddress>(addr));
    if (err) { FAIL("get_device_id"); signal_error_free(err); goto done; }
    if (device_id != 1) { FAIL("device_id mismatch"); goto done; }

    PASS();

done:
    signal_address_destroy(addr);
}

// Test 6: AES-256-GCM-SIV encryption/decryption
void test_aes256_gcm_siv() {
    TEST(Aes256GcmSiv);

    uint8_t key_data[32];
    for (int i = 0; i < 32; i++) key_data[i] = (uint8_t)i;
    uint8_t nonce[12] = {0};
    uint8_t aad[16] = {0};
    const char* plaintext = "Hello, Signal!";
    size_t pt_len = strlen(plaintext);

    SignalMutPointerAes256GcmSiv cipher = {nullptr};
    SignalOwnedBuffer ciphertext = {nullptr, 0};
    SignalOwnedBuffer decrypted = {nullptr, 0};

    SignalBorrowedBuffer key_buf = {key_data, 32};
    SignalFfiError* err = signal_aes256_gcm_siv_new(&cipher, key_buf);
    if (err) { FAIL("new"); signal_error_free(err); return; }

    {
        SignalBorrowedBuffer pt_buf = {(const uint8_t*)plaintext, pt_len};
        SignalBorrowedBuffer nonce_buf = {nonce, 12};
        SignalBorrowedBuffer aad_buf = {aad, 16};

        err = signal_aes256_gcm_siv_encrypt(&ciphertext,
            as_const<SignalConstPointerAes256GcmSiv>(cipher), pt_buf, nonce_buf, aad_buf);
        if (err) { FAIL("encrypt"); signal_error_free(err); goto done; }

        SignalBorrowedBuffer ct_buf = {ciphertext.base, ciphertext.length};
        err = signal_aes256_gcm_siv_decrypt(&decrypted,
            as_const<SignalConstPointerAes256GcmSiv>(cipher), ct_buf, nonce_buf, aad_buf);
        if (err) { FAIL("decrypt"); signal_error_free(err); goto done; }
    }

    if (decrypted.length != pt_len || memcmp(decrypted.base, plaintext, pt_len) != 0) {
        FAIL("decrypted text doesn't match");
    } else {
        PASS();
    }

done:
    if (ciphertext.base) signal_free_buffer(ciphertext.base, ciphertext.length);
    if (decrypted.base) signal_free_buffer(decrypted.base, decrypted.length);
    signal_aes256_gcm_siv_destroy(cipher);
}

// Test 7: HKDF
void test_hkdf() {
    TEST(HKDF_DeriveSecrets);

    uint8_t ikm[32];
    for (int i = 0; i < 32; i++) ikm[i] = (uint8_t)i;
    uint8_t salt[32] = {0};
    uint8_t info[] = "test info";
    uint8_t output[42] = {0};

    SignalBorrowedBuffer ikm_buf = {ikm, 32};
    SignalBorrowedBuffer salt_buf = {salt, 32};
    SignalBorrowedBuffer info_buf = {info, sizeof(info) - 1};
    SignalBorrowedMutableBuffer output_buf = {output, 42};

    SignalFfiError* err = signal_hkdf_derive(output_buf, ikm_buf, info_buf, salt_buf);
    if (err) { FAIL("hkdf_derive failed"); signal_error_free(err); return; }

    bool all_zero = true;
    for (int i = 0; i < 42; i++) {
        if (output[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) { FAIL("output is all zeros"); return; }
    PASS();
}

// Test 8: AccountEntropyPool
void test_account_entropy_pool() {
    TEST(AccountEntropyPool_Generate);

    const char* pool = nullptr;
    SignalFfiError* err = signal_account_entropy_pool_generate(&pool);
    if (err) { FAIL("generate failed"); signal_error_free(err); return; }
    if (!pool || strlen(pool) == 0) { FAIL("empty pool"); return; }

    bool valid = false;
    err = signal_account_entropy_pool_is_valid(&valid, pool);
    if (err) { FAIL("is_valid failed"); signal_free_string(pool); signal_error_free(err); return; }
    if (!valid) { FAIL("pool not valid"); signal_free_string(pool); return; }

    signal_free_string(pool);
    PASS();
}

// Test 9: Identity key pair operations
void test_identity_key_pair() {
    TEST(IdentityKeyPair);

    SignalMutPointerPrivateKey privKey = {nullptr};
    SignalMutPointerPublicKey pubKey = {nullptr};
    SignalOwnedBuffer pub_serialized = {nullptr, 0};
    SignalOwnedBuffer priv_serialized = {nullptr, 0};

    SignalFfiError* err = signal_privatekey_generate(&privKey);
    if (err) { FAIL("generate"); signal_error_free(err); return; }

    err = signal_privatekey_get_public_key(&pubKey, as_const<SignalConstPointerPrivateKey>(privKey));
    if (err) { FAIL("get_public_key"); signal_error_free(err); signal_privatekey_destroy(privKey); return; }

    // Serialize both and verify they can be combined into an identity key pair
    err = signal_publickey_serialize(&pub_serialized, as_const<SignalConstPointerPublicKey>(pubKey));
    if (err) { FAIL("serialize pub"); signal_error_free(err); goto done; }

    err = signal_privatekey_serialize(&priv_serialized, as_const<SignalConstPointerPrivateKey>(privKey));
    if (err) { FAIL("serialize priv"); signal_error_free(err); goto done; }

    if (pub_serialized.length != 33 || priv_serialized.length != 32) {
        char msg[128];
        snprintf(msg, sizeof(msg), "unexpected sizes: pub=%zu, priv=%zu",
                 pub_serialized.length, priv_serialized.length);
        FAIL(msg);
    } else {
        PASS();
    }

done:
    if (pub_serialized.base) signal_free_buffer(pub_serialized.base, pub_serialized.length);
    if (priv_serialized.base) signal_free_buffer(priv_serialized.base, priv_serialized.length);
    signal_publickey_destroy(pubKey);
    signal_privatekey_destroy(privKey);
}

// Test 10: Private key signing
void test_private_key_sign() {
    TEST(PrivateKey_Sign);

    SignalMutPointerPrivateKey priv = {nullptr};
    SignalMutPointerPublicKey pub = {nullptr};
    SignalOwnedBuffer signature = {nullptr, 0};

    SignalFfiError* err = signal_privatekey_generate(&priv);
    if (err) { FAIL("generate"); signal_error_free(err); return; }
    err = signal_privatekey_get_public_key(&pub, as_const<SignalConstPointerPrivateKey>(priv));
    if (err) { FAIL("get_public_key"); signal_error_free(err); signal_privatekey_destroy(priv); return; }

    uint8_t message[] = "test message to sign";
    SignalBorrowedBuffer msg_buf = {message, sizeof(message) - 1};

    err = signal_privatekey_sign(&signature, as_const<SignalConstPointerPrivateKey>(priv), msg_buf);
    if (err) { FAIL("sign"); signal_error_free(err); goto done; }

    if (signature.length != 64) {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 64 byte sig, got %zu", signature.length);
        FAIL(buf);
    } else {
        // Verify the signature
        bool valid = false;
        err = signal_publickey_verify(&valid,
            as_const<SignalConstPointerPublicKey>(pub), msg_buf,
            {signature.base, signature.length});
        if (err) { FAIL("verify"); signal_error_free(err); goto done; }
        if (!valid) { FAIL("signature not valid"); goto done; }
        PASS();
    }

done:
    if (signature.base) signal_free_buffer(signature.base, signature.length);
    signal_publickey_destroy(pub);
    signal_privatekey_destroy(priv);
}

// Test 11: Fingerprint comparison
void test_fingerprint() {
    TEST(Fingerprint_Compare);

    // Create two identity keys
    SignalMutPointerPrivateKey priv1 = {nullptr}, priv2 = {nullptr};
    SignalMutPointerPublicKey pub1 = {nullptr}, pub2 = {nullptr};
    SignalOwnedBuffer pub1_ser = {nullptr, 0}, pub2_ser = {nullptr, 0};
    SignalMutPointerFingerprint fp1 = {nullptr}, fp2 = {nullptr};
    const char* display1 = nullptr;
    const char* display2 = nullptr;

    SignalFfiError* err = signal_privatekey_generate(&priv1);
    if (err) { FAIL("gen1"); signal_error_free(err); return; }
    err = signal_privatekey_generate(&priv2);
    if (err) { FAIL("gen2"); signal_error_free(err); signal_privatekey_destroy(priv1); return; }

    err = signal_privatekey_get_public_key(&pub1, as_const<SignalConstPointerPrivateKey>(priv1));
    if (err) { FAIL("pub1"); signal_error_free(err); goto done; }
    err = signal_privatekey_get_public_key(&pub2, as_const<SignalConstPointerPrivateKey>(priv2));
    if (err) { FAIL("pub2"); signal_error_free(err); goto done; }

    err = signal_publickey_serialize(&pub1_ser, as_const<SignalConstPointerPublicKey>(pub1));
    if (err) { FAIL("ser1"); signal_error_free(err); goto done; }
    err = signal_publickey_serialize(&pub2_ser, as_const<SignalConstPointerPublicKey>(pub2));
    if (err) { FAIL("ser2"); signal_error_free(err); goto done; }

    {
        uint8_t stable_id[] = "+14155550100";
        SignalBorrowedBuffer id_buf = {stable_id, sizeof(stable_id) - 1};

        err = signal_fingerprint_new(&fp1, 5200, 2, id_buf,
            as_const<SignalConstPointerPublicKey>(pub1), id_buf,
            as_const<SignalConstPointerPublicKey>(pub2));
        if (err) { FAIL("fp1_new"); signal_error_free(err); goto done; }

        err = signal_fingerprint_new(&fp2, 5200, 2, id_buf,
            as_const<SignalConstPointerPublicKey>(pub2), id_buf,
            as_const<SignalConstPointerPublicKey>(pub1));
        if (err) { FAIL("fp2_new"); signal_error_free(err); goto done; }
    }

    err = signal_fingerprint_display_string(&display1,
        as_const<SignalConstPointerFingerprint>(fp1));
    if (err) { FAIL("display1"); signal_error_free(err); goto done; }

    err = signal_fingerprint_display_string(&display2,
        as_const<SignalConstPointerFingerprint>(fp2));
    if (err) { FAIL("display2"); signal_error_free(err); goto done; }

    // Both fingerprints should produce the same display string (they're the same keys)
    if (!display1 || !display2 || strlen(display1) == 0 || strlen(display2) == 0) {
        FAIL("empty display string");
    } else if (strcmp(display1, display2) != 0) {
        FAIL("display strings don't match");
    } else {
        PASS();
    }

done:
    if (display1) signal_free_string(display1);
    if (display2) signal_free_string(display2);
    if (fp1.raw) signal_fingerprint_destroy(fp1);
    if (fp2.raw) signal_fingerprint_destroy(fp2);
    if (pub1_ser.base) signal_free_buffer(pub1_ser.base, pub1_ser.length);
    if (pub2_ser.base) signal_free_buffer(pub2_ser.base, pub2_ser.length);
    signal_publickey_destroy(pub1);
    signal_publickey_destroy(pub2);
    signal_privatekey_destroy(priv1);
    signal_privatekey_destroy(priv2);
}

// Test 12: Sealed sender certificate round-trip
void test_sealed_sender_cert() {
    TEST(SealedSenderCert);

    // Create a server certificate
    SignalMutPointerPrivateKey serverPriv = {nullptr};
    SignalMutPointerPublicKey serverPub = {nullptr};
    SignalOwnedBuffer serverPubSer = {nullptr, 0};
    SignalMutPointerServerCertificate serverCert = {nullptr};
    SignalOwnedBuffer serverCertSer = {nullptr, 0};
    SignalMutPointerServerCertificate serverCertDeser = {nullptr};

    SignalFfiError* err = signal_privatekey_generate(&serverPriv);
    if (err) { FAIL("gen server key"); signal_error_free(err); return; }

    err = signal_privatekey_get_public_key(&serverPub, as_const<SignalConstPointerPrivateKey>(serverPriv));
    if (err) { FAIL("get server pub"); signal_error_free(err); signal_privatekey_destroy(serverPriv); return; }

    err = signal_publickey_serialize(&serverPubSer, as_const<SignalConstPointerPublicKey>(serverPub));
    if (err) { FAIL("ser server pub"); signal_error_free(err); goto done; }

    {
        err = signal_server_certificate_new(&serverCert, 1,
            as_const<SignalConstPointerPublicKey>(serverPub),
            as_const<SignalConstPointerPrivateKey>(serverPriv));
        if (err) { FAIL("server_cert_new"); signal_error_free(err); goto done; }
    }

    err = signal_server_certificate_get_serialized(&serverCertSer,
        as_const<SignalConstPointerServerCertificate>(serverCert));
    if (err) { FAIL("get_serialized"); signal_error_free(err); goto done; }

    {
        SignalBorrowedBuffer cert_buf = {serverCertSer.base, serverCertSer.length};
        err = signal_server_certificate_deserialize(&serverCertDeser, cert_buf);
        if (err) { FAIL("deserialize"); signal_error_free(err); goto done; }
    }

    if (!serverCertDeser.raw) {
        FAIL("deserialized is null");
    } else {
        PASS();
    }

done:
    if (serverCertDeser.raw) signal_server_certificate_destroy(serverCertDeser);
    if (serverCertSer.base) signal_free_buffer(serverCertSer.base, serverCertSer.length);
    if (serverCert.raw) signal_server_certificate_destroy(serverCert);
    if (serverPubSer.base) signal_free_buffer(serverPubSer.base, serverPubSer.length);
    signal_publickey_destroy(serverPub);
    signal_privatekey_destroy(serverPriv);
}

int main() {
    printf("=== libsignal FFI Host Integration Tests ===\n\n");

    test_private_key_generate();
    test_public_key_from_private();
    test_public_key_roundtrip();
    test_ecdh_agreement();
    test_protocol_address();
    test_aes256_gcm_siv();
    test_hkdf();
    test_account_entropy_pool();
    test_identity_key_pair();
    test_private_key_sign();
    test_fingerprint();
    test_sealed_sender_cert();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
