//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * React Native bindings for libsignal-client.
 *
 * Before using any exports from this module, you must install the native module:
 *
 * ```typescript
 * import { install } from '@aspect-build/react-native-libsignal';
 * install(); // Call once at app startup
 * ```
 *
 * Then use the high-level API:
 *
 * ```typescript
 * import { PrivateKey, PublicKey, hkdf, Fingerprint } from '@aspect-build/react-native-libsignal';
 *
 * const key = PrivateKey.generate();
 * const pub = key.getPublicKey();
 * const sig = key.sign(message);
 * const valid = pub.verify(message, sig);
 * ```
 */

import { NativeModules } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-libsignal' doesn't seem to be linked. Make sure: \n\n` +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go (custom native modules require a dev build)\n';

/**
 * Install the libsignal JSI bindings into the JS runtime.
 * This must be called once before using any libsignal functions.
 */
export function install(): boolean {
  const libsignal = NativeModules.Libsignal;
  if (!libsignal) {
    throw new Error(LINKING_ERROR);
  }
  return libsignal.install();
}

// High-level typed API
export { PublicKey, PrivateKey, IdentityKeyPair } from './EcKeys';
export { ProtocolAddress } from './Address';
export {
  Fingerprint,
  DisplayableFingerprint,
  ScannableFingerprint,
} from './Fingerprint';
export { Aes256GcmSiv, hkdf } from './Crypto';
export {
  AccountEntropyPool,
  KEMPublicKey,
  KEMSecretKey,
  KEMKeyPair,
} from './AccountKeys';
export { LibSignalError, InvalidKeyError, InvalidSignatureError, ErrorCode } from './Errors';

// Re-export low-level Native types for advanced usage
import * as _Native from './Native';
export { _Native as Native };
