//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * React Native bindings for libsignal-client.
 *
 * Before using any exports from this module, you must install the native module:
 *
 * Android (Java):
 *   LibsignalModule module = new LibsignalModule(reactContext);
 *   module.install();
 *
 * iOS (ObjC) — handled automatically via RCT_EXPORT_MODULE.
 *
 * Then in JavaScript:
 *   import { install } from '@aspect-build/react-native-libsignal';
 *   install(); // ensures native module is loaded
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

// Re-export everything from the Native module
export * from './Native';
