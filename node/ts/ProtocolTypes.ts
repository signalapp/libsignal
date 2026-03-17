//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';
import { PrivateKey, PublicKey } from './EcKeys.js';

export class KEMPublicKey {
  readonly _nativeHandle: Native.KyberPublicKey;

  private constructor(handle: Native.KyberPublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberPublicKey): KEMPublicKey {
    return new KEMPublicKey(handle);
  }

  static deserialize(buf: Uint8Array<ArrayBuffer>): KEMPublicKey {
    return new KEMPublicKey(Native.KyberPublicKey_Deserialize(buf));
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.KyberPublicKey_Serialize(this);
  }
}

export class SignedPreKeyRecord implements SignedPublicPreKey {
  readonly _nativeHandle: Native.SignedPreKeyRecord;

  private constructor(handle: Native.SignedPreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SignedPreKeyRecord
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(nativeHandle);
  }

  static new(
    id: number,
    timestamp: number,
    pubKey: PublicKey,
    privKey: PrivateKey,
    signature: Uint8Array<ArrayBuffer>
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      Native.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature)
    );
  }

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      Native.SignedPreKeyRecord_Deserialize(buffer)
    );
  }

  id(): number {
    return Native.SignedPreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      Native.SignedPreKeyRecord_GetPrivateKey(this)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      Native.SignedPreKeyRecord_GetPublicKey(this)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.SignedPreKeyRecord_Serialize(this);
  }

  signature(): Uint8Array<ArrayBuffer> {
    return Native.SignedPreKeyRecord_GetSignature(this);
  }

  timestamp(): number {
    return Native.SignedPreKeyRecord_GetTimestamp(this);
  }
}

/** The public information contained in a {@link SignedPreKeyRecord} */
export type SignedPublicPreKey = {
  id: () => number;
  publicKey: () => PublicKey;
  signature: () => Uint8Array<ArrayBuffer>;
};

export class PreKeyBundle {
  readonly _nativeHandle: Native.PreKeyBundle;

  private constructor(handle: Native.PreKeyBundle) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PreKeyBundle): PreKeyBundle {
    return new PreKeyBundle(handle);
  }

  static new(
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: PublicKey | null,
    signed_prekey_id: number,
    signed_prekey: PublicKey,
    signed_prekey_signature: Uint8Array<ArrayBuffer>,
    identity_key: PublicKey,
    kyber_prekey_id: number,
    kyber_prekey: KEMPublicKey,
    kyber_prekey_signature: Uint8Array<ArrayBuffer>
  ): PreKeyBundle {
    return new PreKeyBundle(
      Native.PreKeyBundle_New(
        registration_id,
        device_id,
        prekey_id,
        prekey,
        signed_prekey_id,
        signed_prekey,
        signed_prekey_signature,
        identity_key,
        kyber_prekey_id,
        kyber_prekey,
        kyber_prekey_signature
      )
    );
  }

  deviceId(): number {
    return Native.PreKeyBundle_GetDeviceId(this);
  }
  identityKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      Native.PreKeyBundle_GetIdentityKey(this)
    );
  }
  preKeyId(): number | null {
    return Native.PreKeyBundle_GetPreKeyId(this);
  }
  preKeyPublic(): PublicKey | null {
    const handle = Native.PreKeyBundle_GetPreKeyPublic(this);

    if (handle == null) {
      return null;
    } else {
      return PublicKey._fromNativeHandle(handle);
    }
  }
  registrationId(): number {
    return Native.PreKeyBundle_GetRegistrationId(this);
  }
  signedPreKeyId(): number {
    return Native.PreKeyBundle_GetSignedPreKeyId(this);
  }
  signedPreKeyPublic(): PublicKey {
    return PublicKey._fromNativeHandle(
      Native.PreKeyBundle_GetSignedPreKeyPublic(this)
    );
  }
  signedPreKeySignature(): Uint8Array<ArrayBuffer> {
    return Native.PreKeyBundle_GetSignedPreKeySignature(this);
  }

  kyberPreKeyId(): number {
    return Native.PreKeyBundle_GetKyberPreKeyId(this);
  }

  kyberPreKeyPublic(): KEMPublicKey {
    return KEMPublicKey._fromNativeHandle(
      Native.PreKeyBundle_GetKyberPreKeyPublic(this)
    );
  }

  kyberPreKeySignature(): Uint8Array<ArrayBuffer> {
    return Native.PreKeyBundle_GetKyberPreKeySignature(this);
  }
}
