//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native';
import { PublicKey } from './EcKeys';

function getNative(): any {
  return (globalThis as any).__libsignal_native;
}

/**
 * A displayable fingerprint (numeric string for human comparison).
 */
export class DisplayableFingerprint {
  private readonly displayString: string;

  constructor(displayString: string) {
    this.displayString = displayString;
  }

  /**
   * Get the displayable fingerprint string (e.g., "12345 67890 ...").
   */
  toString(): string {
    return this.displayString;
  }
}

/**
 * A scannable fingerprint (binary data for QR code comparison).
 */
export class ScannableFingerprint {
  private readonly _nativeHandle: Native.Fingerprint;

  constructor(nativeHandle: Native.Fingerprint) {
    this._nativeHandle = nativeHandle;
  }

  /**
   * Serialize this scannable fingerprint to bytes.
   */
  toBuffer(): Uint8Array {
    const n = getNative();
    return n.ScannableFingerprint_Serialize(this._nativeHandle);
  }

  /**
   * Compare this scannable fingerprint with another.
   * Returns true if they match.
   */
  compare(other: Uint8Array): boolean {
    const n = getNative();
    return n.ScannableFingerprint_Compare(
      this.toBuffer(),
      other
    );
  }
}

/**
 * A fingerprint for verifying identity keys.
 *
 * Contains both a displayable (numeric) representation and a scannable (binary)
 * representation for verifying that two parties have the same view of each
 * other's identity keys.
 */
export class Fingerprint {
  readonly _nativeHandle: Native.Fingerprint;

  private constructor(handle: Native.Fingerprint) {
    this._nativeHandle = handle;
  }

  /**
   * Create a new fingerprint.
   * @param iterations Number of hash iterations (typically 1024 or 5200)
   * @param version Protocol version
   * @param localIdentifier Local user's identifier (e.g., phone number hash)
   * @param localKey Local user's identity public key
   * @param remoteIdentifier Remote user's identifier
   * @param remoteKey Remote user's identity public key
   */
  static new(
    iterations: number,
    version: number,
    localIdentifier: Uint8Array,
    localKey: PublicKey,
    remoteIdentifier: Uint8Array,
    remoteKey: PublicKey
  ): Fingerprint {
    const n = getNative();
    return new Fingerprint(
      n.Fingerprint_New(
        iterations,
        version,
        localIdentifier,
        localKey._nativeHandle,
        remoteIdentifier,
        remoteKey._nativeHandle
      )
    );
  }

  /**
   * Get the displayable (numeric) fingerprint.
   */
  displayableFingerprint(): DisplayableFingerprint {
    const n = getNative();
    return new DisplayableFingerprint(
      n.Fingerprint_DisplayString(this._nativeHandle)
    );
  }

  /**
   * Get the scannable (binary) fingerprint.
   */
  scannableFingerprint(): ScannableFingerprint {
    return new ScannableFingerprint(this._nativeHandle);
  }
}
