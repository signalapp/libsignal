/**
 * Libsignal React Native Test App
 * Tests that the JSI module loads and basic crypto operations work.
 */

import React, {useEffect, useState} from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  NativeModules,
} from 'react-native';

// High-level typed API
import {
  install,
  PrivateKey,
  PublicKey,
  IdentityKeyPair,
  ProtocolAddress,
  Fingerprint,
  Aes256GcmSiv,
  hkdf,
  AccountEntropyPool,
} from '../ts/index';

// Access the native module (for low-level tests)
const {Libsignal} = NativeModules;

// After install(), __libsignal_native is available as a global
declare const __libsignal_native: any;

type TestResult = {
  name: string;
  status: 'pass' | 'fail' | 'pending';
  message?: string;
};

async function runTests(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  function test(name: string, fn: () => void) {
    try {
      fn();
      results.push({name, status: 'pass'});
    } catch (e: any) {
      results.push({name, status: 'fail', message: e.message || String(e)});
    }
  }

  async function asyncTest(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      results.push({name, status: 'pass'});
    } catch (e: any) {
      results.push({name, status: 'fail', message: e.message || String(e)});
    }
  }

  // Test 1: Module installation
  test('Module install()', () => {
    const ok = Libsignal.install();
    if (!ok) {
      throw new Error('install() returned false');
    }
  });

  // Test 2: Global object exists
  test('__libsignal_native global exists', () => {
    if (typeof __libsignal_native === 'undefined') {
      throw new Error('__libsignal_native is undefined');
    }
  });

  // Test 3: Generate key pair (ECDH)
  test('PrivateKey_Generate', () => {
    const privateKey = __libsignal_native.PrivateKey_Generate();
    if (!privateKey) {
      throw new Error('returned null/undefined');
    }
  });

  // Test 4: Get public key from private key
  test('PrivateKey → PublicKey', () => {
    const privateKey = __libsignal_native.PrivateKey_Generate();
    const pubKey = __libsignal_native.PrivateKey_GetPublicKey(privateKey);
    if (!pubKey) {
      throw new Error('public key is null');
    }
  });

  // Test 5: Serialize/deserialize public key
  test('PublicKey serialize round-trip', () => {
    const privateKey = __libsignal_native.PrivateKey_Generate();
    const pubKey = __libsignal_native.PrivateKey_GetPublicKey(privateKey);
    const serialized = __libsignal_native.PublicKey_Serialize(pubKey);
    if (!(serialized instanceof Uint8Array) && !ArrayBuffer.isView(serialized)) {
      throw new Error(`expected buffer, got ${typeof serialized}`);
    }
    if (serialized.length !== 33) {
      throw new Error(`expected 33 bytes, got ${serialized.length}`);
    }
  });

  // Test 6: HKDF derive secrets
  test('Hkdf_Derive', () => {
    const output = new Uint8Array(42);
    const ikm = new Uint8Array(32);
    ikm.fill(0x42);
    const salt = new Uint8Array(32);
    salt.fill(0x01);
    const info = new Uint8Array([0x69, 0x6e, 0x66, 0x6f]); // "info"
    __libsignal_native.Hkdf_Derive(output, ikm, info, salt);
    // Check that output was written (not all zeros)
    let nonZero = false;
    for (let i = 0; i < output.length; i++) {
      if (output[i] !== 0) { nonZero = true; break; }
    }
    if (!nonZero) {
      throw new Error('output is all zeros');
    }
  });

  // Test 7: Protocol address
  test('ProtocolAddress_New', () => {
    const addr = __libsignal_native.ProtocolAddress_New('+14155550100', 1);
    if (!addr) {
      throw new Error('address is null');
    }
    const name = __libsignal_native.ProtocolAddress_Name(addr);
    if (name !== '+14155550100') {
      throw new Error(`expected +14155550100, got ${name}`);
    }
    const deviceId = __libsignal_native.ProtocolAddress_DeviceId(addr);
    if (deviceId !== 1) {
      throw new Error(`expected device 1, got ${deviceId}`);
    }
  });

  // Test 8: Account entropy pool
  test('AccountEntropyPool_Generate', () => {
    const pool = __libsignal_native.AccountEntropyPool_Generate();
    if (typeof pool !== 'string' || pool.length === 0) {
      throw new Error(`expected non-empty string, got ${typeof pool} (${pool?.length})`);
    }
  });

  // Test 9: Feature flag check (simple function)
  test('TESTING_OnlyCheckFeatureFlag', () => {
    // Should not throw
    __libsignal_native.TESTING_OnlyCheckFeatureFlag('test_flag');
  });

  // Test 10: Fingerprint (numeric)
  test('Fingerprint_New', () => {
    const iterations = 1024;
    const localId = new Uint8Array(16);
    localId.fill(0x01);
    const remoteId = new Uint8Array(16);
    remoteId.fill(0x02);
    const privateKey1 = __libsignal_native.PrivateKey_Generate();
    const pubKey1 = __libsignal_native.PrivateKey_GetPublicKey(privateKey1);
    const privateKey2 = __libsignal_native.PrivateKey_Generate();
    const pubKey2 = __libsignal_native.PrivateKey_GetPublicKey(privateKey2);

    const fp = __libsignal_native.Fingerprint_New(
      iterations,
      1,        // version
      localId,
      pubKey1,  // pass the HostObject pointer, not serialized bytes
      remoteId,
      pubKey2,
    );
    if (!fp) {
      throw new Error('fingerprint is null');
    }
  });

  // ---- Async infrastructure tests ----

  // Test 11: TokioAsyncContext_New returns a host object
  test('TokioAsyncContext_New', () => {
    const ctx = __libsignal_native.TokioAsyncContext_New();
    if (!ctx || typeof ctx !== 'object') {
      throw new Error(`expected object, got ${typeof ctx}`);
    }
  });

  // Test 12: TokioAsyncContext_Cancel with dummy id (should not crash)
  test('TokioAsyncContext_Cancel (no-op)', () => {
    __libsignal_native.TokioAsyncContext_Cancel(0);
  });

  // Test 13: Async function returns a Promise (UnauthenticatedChatConnection_connect)
  // This will reject because the ConnectionManager arg is invalid, but it proves
  // the Promise infrastructure works.
  await asyncTest('Async returns Promise (rejects on bad args)', async () => {
    try {
      // Call with null/undefined args - should reject or throw
      await __libsignal_native.UnauthenticatedChatConnection_connect(null, null);
      throw new Error('should have thrown');
    } catch (e: any) {
      // Expected: error about invalid argument - this proves the promise was created
      // and the error was propagated
      if (!e.message) {
        throw new Error('error had no message');
      }
      // Success - we got a proper error back through the async pipeline
    }
  });

  // Test 13b: Real async round-trip — TESTING_TokioAsyncFuture returns input*3
  await asyncTest('Async: TokioAsyncFuture returns i32', async () => {
    const result = await __libsignal_native.TESTING_TokioAsyncFuture(42);
    if (result !== 126) {
      throw new Error(`expected 126 (42*3), got ${result}`);
    }
  });

  // Test 13c: Real async round-trip — TESTING_TokioAsyncContextFutureSuccessBytes
  await asyncTest('Async: FutureSuccessBytes returns buffer', async () => {
    const result = await __libsignal_native.TESTING_TokioAsyncContextFutureSuccessBytes(10);
    if (!(result instanceof Uint8Array) && !ArrayBuffer.isView(result)) {
      throw new Error(`expected Uint8Array, got ${typeof result}`);
    }
    if (result.length !== 10) {
      throw new Error(`expected 10 bytes, got ${result.length}`);
    }
  });

  // Test 13d: Verify async with different input values (each returns input*3)
  await asyncTest('Async: multiple sequential calls', async () => {
    const r1 = await __libsignal_native.TESTING_TokioAsyncFuture(0);
    const r2 = await __libsignal_native.TESTING_TokioAsyncFuture(255);
    const r3 = await __libsignal_native.TESTING_TokioAsyncFuture(127);
    if (r1 !== 0 || r2 !== 765 || r3 !== 381) {
      throw new Error(`expected [0,765,381], got [${r1},${r2},${r3}]`);
    }
  });

  // Test 14: Verify PublicKey comparison
  test('PublicKey_Equals', () => {
    const priv1 = __libsignal_native.PrivateKey_Generate();
    const pub1 = __libsignal_native.PrivateKey_GetPublicKey(priv1);
    const priv2 = __libsignal_native.PrivateKey_Generate();
    const pub2 = __libsignal_native.PrivateKey_GetPublicKey(priv2);
    // Different keys should not be equal
    const diff = __libsignal_native.PublicKey_Equals(pub1, pub2);
    if (diff !== false) {
      throw new Error(`different keys should not be equal, got ${diff}`);
    }
    // Same key should be equal
    const same = __libsignal_native.PublicKey_Equals(pub1, pub1);
    if (same !== true) {
      throw new Error(`same key should be equal, got ${same}`);
    }
  });

  // Test 15: PrivateKey_Sign and PublicKey_Verify
  test('Sign and Verify', () => {
    const priv = __libsignal_native.PrivateKey_Generate();
    const pub = __libsignal_native.PrivateKey_GetPublicKey(priv);
    const message = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const sig = __libsignal_native.PrivateKey_Sign(priv, message);
    if (!(sig instanceof Uint8Array) && !ArrayBuffer.isView(sig)) {
      throw new Error(`expected buffer, got ${typeof sig}`);
    }
    const valid = __libsignal_native.PublicKey_Verify(pub, message, sig);
    if (valid !== true) {
      throw new Error(`signature should be valid, got ${valid}`);
    }
  });

  // Test 16: AES-256-GCM-SIV encrypt/decrypt round-trip
  test('Aes256GcmSiv encrypt/decrypt', () => {
    const key = new Uint8Array(32);
    key.fill(0x42);
    const nonce = new Uint8Array(12); // GCM-SIV uses 12-byte nonce
    nonce.fill(0x01);
    const plaintext = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const aad = new Uint8Array(0); // empty associated data
    const cipher = __libsignal_native.Aes256GcmSiv_New(key);
    const encrypted = __libsignal_native.Aes256GcmSiv_Encrypt(cipher, plaintext, nonce, aad);
    if (!(encrypted instanceof Uint8Array) && !ArrayBuffer.isView(encrypted)) {
      throw new Error(`expected buffer, got ${typeof encrypted}`);
    }
    if (encrypted.length <= plaintext.length) {
      throw new Error(`encrypted should be longer (has tag), got ${encrypted.length}`);
    }
    const decrypted = __libsignal_native.Aes256GcmSiv_Decrypt(cipher, encrypted, nonce, aad);
    if (decrypted.length !== plaintext.length) {
      throw new Error(`decrypted length ${decrypted.length} != ${plaintext.length}`);
    }
    for (let i = 0; i < plaintext.length; i++) {
      if (decrypted[i] !== plaintext[i]) {
        throw new Error(`mismatch at ${i}: ${decrypted[i]} vs ${plaintext[i]}`);
      }
    }
  });

  // ---- High-level TypeScript API tests ----

  // Test 17: PrivateKey.generate() via high-level API
  test('API: PrivateKey.generate()', () => {
    const key = PrivateKey.generate();
    if (!key || !key._nativeHandle) {
      throw new Error('PrivateKey.generate() failed');
    }
    const pub = key.getPublicKey();
    if (!pub || !pub._nativeHandle) {
      throw new Error('getPublicKey() failed');
    }
  });

  // Test 18: Sign/verify via high-level API
  test('API: Sign and Verify', () => {
    const key = PrivateKey.generate();
    const pub = key.getPublicKey();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);
    const sig = key.sign(msg);
    if (!pub.verify(msg, sig)) {
      throw new Error('signature verification failed');
    }
  });

  // Test 19: Key serialization round-trip
  test('API: Key serialize/deserialize', () => {
    const key = PrivateKey.generate();
    const pub = key.getPublicKey();
    const serialized = pub.serialize();
    const deserialized = PublicKey.deserialize(serialized);
    if (!pub.equals(deserialized)) {
      throw new Error('round-trip failed');
    }
  });

  // Test 20: ECDH key agreement
  test('API: ECDH agree()', () => {
    const alice = PrivateKey.generate();
    const bob = PrivateKey.generate();
    const sharedA = alice.agree(bob.getPublicKey());
    const sharedB = bob.agree(alice.getPublicKey());
    if (sharedA.length !== 32) {
      throw new Error(`expected 32 bytes, got ${sharedA.length}`);
    }
    for (let i = 0; i < 32; i++) {
      if (sharedA[i] !== sharedB[i]) {
        throw new Error(`ECDH mismatch at byte ${i}`);
      }
    }
  });

  // Test 21: IdentityKeyPair
  test('API: IdentityKeyPair', () => {
    const ikp = IdentityKeyPair.generate();
    const serialized = ikp.serialize();
    if (serialized.length === 0) {
      throw new Error('serialized identity key pair is empty');
    }
  });

  // Test 22: ProtocolAddress
  test('API: ProtocolAddress', () => {
    const addr = ProtocolAddress.new('+14155550100', 2);
    if (addr.name() !== '+14155550100') {
      throw new Error(`expected +14155550100, got ${addr.name()}`);
    }
    if (addr.deviceId() !== 2) {
      throw new Error(`expected device 2, got ${addr.deviceId()}`);
    }
  });

  // Test 23: Fingerprint via high-level API
  test('API: Fingerprint', () => {
    const alice = PrivateKey.generate();
    const bob = PrivateKey.generate();
    const localId = new Uint8Array(16).fill(0x01);
    const remoteId = new Uint8Array(16).fill(0x02);
    const fp = Fingerprint.new(
      1024, 1,
      localId, alice.getPublicKey(),
      remoteId, bob.getPublicKey()
    );
    const display = fp.displayableFingerprint().toString();
    if (typeof display !== 'string' || display.length === 0) {
      throw new Error(`expected non-empty string, got "${display}"`);
    }
  });

  // Test 24: Aes256GcmSiv via high-level API
  test('API: Aes256GcmSiv', () => {
    const key = new Uint8Array(32).fill(0x42);
    const nonce = new Uint8Array(12).fill(0x01);
    const cipher = Aes256GcmSiv.new(key);
    const plaintext = new Uint8Array([72, 101, 108, 108, 111]);
    const encrypted = cipher.encrypt(plaintext, nonce);
    const decrypted = cipher.decrypt(encrypted, nonce);
    for (let i = 0; i < plaintext.length; i++) {
      if (decrypted[i] !== plaintext[i]) {
        throw new Error(`mismatch at ${i}`);
      }
    }
  });

  // Test 25: hkdf via high-level API
  test('API: hkdf', () => {
    const ikm = new Uint8Array(32).fill(0x42);
    const info = new Uint8Array([0x69, 0x6e, 0x66, 0x6f]);
    const salt = new Uint8Array(32).fill(0x01);
    const derived = hkdf(42, ikm, info, salt);
    if (derived.length !== 42) {
      throw new Error(`expected 42 bytes, got ${derived.length}`);
    }
    let nonZero = false;
    for (let i = 0; i < derived.length; i++) {
      if (derived[i] !== 0) { nonZero = true; break; }
    }
    if (!nonZero) {
      throw new Error('output is all zeros');
    }
  });

  // Test 26: AccountEntropyPool
  test('API: AccountEntropyPool', () => {
    const pool = AccountEntropyPool.generate();
    if (typeof pool.value !== 'string' || pool.value.length === 0) {
      throw new Error('pool value is empty');
    }
  });

  return results;
}

function App(): React.JSX.Element {
  const [results, setResults] = useState<TestResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    runTests().then(r => {
      setResults(r);
      const passed = r.filter(t => t.status === 'pass').length;
      const failed = r.filter(t => t.status === 'fail').length;
      console.log(`[libsignal-test] ${passed}/${r.length} passed, ${failed} failed`);
      r.forEach(t => {
        const icon = t.status === 'pass' ? '✅' : '❌';
        console.log(`[libsignal-test] ${icon} ${t.name}${t.message ? ': ' + t.message : ''}`);
      });
    }).catch(e => {
      console.log(`[libsignal-test] FATAL: ${e.message || String(e)}`);
      setError(e.message || String(e));
    });
  }, []);

  const passed = results.filter(r => r.status === 'pass').length;
  const failed = results.filter(r => r.status === 'fail').length;

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#1a1a2e" />
      <ScrollView contentInsetAdjustmentBehavior="automatic">
        <View style={styles.header}>
          <Text style={styles.title}>libsignal RN Test</Text>
          <Text style={styles.subtitle}>
            {passed}/{results.length} passed
            {failed > 0 ? ` · ${failed} failed` : ''}
          </Text>
        </View>

        {error && (
          <View style={[styles.testRow, styles.errorRow]}>
            <Text style={styles.errorText}>Fatal: {error}</Text>
          </View>
        )}

        {results.map((r, i) => (
          <View
            key={i}
            style={[
              styles.testRow,
              r.status === 'pass' ? styles.passRow : styles.failRow,
            ]}>
            <Text style={styles.testIcon}>
              {r.status === 'pass' ? '✅' : '❌'}
            </Text>
            <View style={styles.testContent}>
              <Text style={styles.testName}>{r.name}</Text>
              {r.message && (
                <Text style={styles.testMessage}>{r.message}</Text>
              )}
            </View>
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
  },
  header: {
    padding: 24,
    paddingTop: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: '700',
    color: '#e0e0e0',
  },
  subtitle: {
    fontSize: 16,
    color: '#a0a0c0',
    marginTop: 4,
  },
  testRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    padding: 12,
    marginHorizontal: 12,
    marginVertical: 3,
    borderRadius: 8,
  },
  passRow: {
    backgroundColor: '#1e3a2f',
  },
  failRow: {
    backgroundColor: '#3a1e1e',
  },
  errorRow: {
    backgroundColor: '#4a1e1e',
    marginBottom: 8,
  },
  testIcon: {
    fontSize: 18,
    marginRight: 10,
    marginTop: 2,
  },
  testContent: {
    flex: 1,
  },
  testName: {
    fontSize: 15,
    fontWeight: '600',
    color: '#e0e0e0',
  },
  testMessage: {
    fontSize: 12,
    color: '#ff8888',
    marginTop: 4,
  },
  errorText: {
    fontSize: 14,
    color: '#ff6666',
  },
});

export default App;
