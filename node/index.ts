//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as os from 'os';
import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

const SC = bindings('libsignal_client_' + os.platform()) as typeof SignalClient;

export const { initLogger, LogLevel } = SC;

export class Aes256GcmSiv {
  private readonly nativeHandle: SignalClient.Aes256GcmSiv;

  private constructor(key: Buffer) {
    this.nativeHandle = SC.Aes256GcmSiv_New(key);
  }

  static new(key: Buffer): Aes256GcmSiv {
    return new Aes256GcmSiv(key);
  }

  encrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return SC.Aes256GcmSiv_Encrypt(
      this.nativeHandle,
      message,
      nonce,
      associated_data
    );
  }

  decrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return SC.Aes256GcmSiv_Decrypt(
      this.nativeHandle,
      message,
      nonce,
      associated_data
    );
  }
}

export class ProtocolAddress {
  private readonly nativeHandle: SignalClient.ProtocolAddress;

  private constructor(handle: SignalClient.ProtocolAddress) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(
    handle: SignalClient.ProtocolAddress
  ): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(SC.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return SC.ProtocolAddress_Name(this.nativeHandle);
  }

  deviceId(): number {
    return SC.ProtocolAddress_DeviceId(this.nativeHandle);
  }
}

export class PublicKey {
  private readonly nativeHandle: SignalClient.PublicKey;

  private constructor(handle: SignalClient.PublicKey) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(handle: SignalClient.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(SC.PublicKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PublicKey_Serialize(this.nativeHandle);
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return SC.PublicKey_Verify(this.nativeHandle, msg, sig);
  }

  _unsafeGetNativeHandle(): SignalClient.PublicKey {
    return this.nativeHandle;
  }
}

export class PrivateKey {
  private readonly nativeHandle: SignalClient.PrivateKey;

  private constructor(handle: SignalClient.PrivateKey) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(handle: SignalClient.PrivateKey): PrivateKey {
    return new PrivateKey(handle);
  }

  _unsafeGetNativeHandle(): SignalClient.PrivateKey {
    return this.nativeHandle;
  }

  static generate(): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Generate());
  }

  static deserialize(buf: Buffer): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PrivateKey_Serialize(this.nativeHandle);
  }

  sign(msg: Buffer): Buffer {
    return SC.PrivateKey_Sign(this.nativeHandle, msg);
  }

  agree(other_key: PublicKey): Buffer {
    return SC.PrivateKey_Agree(
      this.nativeHandle,
      other_key._unsafeGetNativeHandle()
    );
  }

  getPublicKey(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PrivateKey_GetPublicKey(this.nativeHandle)
    );
  }
}

export class PreKeyBundle {
  private readonly nativeHandle: SignalClient.PreKeyBundle;

  private constructor(handle: SignalClient.PreKeyBundle) {
    this.nativeHandle = handle;
  }

  static new(
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: PublicKey | null,
    signed_prekey_id: number,
    signed_prekey: PublicKey,
    signed_prekey_signature: Buffer,
    identity_key: PublicKey
  ): PreKeyBundle {
    return new PreKeyBundle(
      SC.PreKeyBundle_New(
        registration_id,
        device_id,
        prekey_id,
        prekey != null ? prekey._unsafeGetNativeHandle() : null,
        //prekey?._unsafeGetNativeHandle(),
        signed_prekey_id,
        signed_prekey._unsafeGetNativeHandle(),
        signed_prekey_signature,
        identity_key._unsafeGetNativeHandle()
      )
    );
  }

  deviceId(): number {
    return SC.PreKeyBundle_GetDeviceId(this.nativeHandle);
  }
  identityKey(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PreKeyBundle_GetIdentityKey(this.nativeHandle)
    );
  }
  preKeyId(): number | null {
    return SC.PreKeyBundle_GetPreKeyId(this.nativeHandle);
  }
  preKeyPublic(): PublicKey | null {
    const handle = SC.PreKeyBundle_GetPreKeyPublic(this.nativeHandle);

    if (handle == null) {
      return null;
    } else {
      return PublicKey.fromNativeHandle(handle);
    }
  }
  registrationId(): number {
    return SC.PreKeyBundle_GetRegistrationId(this.nativeHandle);
  }
  signedPreKeyId(): number {
    return SC.PreKeyBundle_GetSignedPreKeyId(this.nativeHandle);
  }
  signedPreKeyPublic(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PreKeyBundle_GetSignedPreKeyPublic(this.nativeHandle)
    );
  }
  signedPreKeySignature(): Buffer {
    return SC.PreKeyBundle_GetSignedPreKeySignature(this.nativeHandle);
  }
}

export class PreKeyRecord {
  private readonly nativeHandle: SignalClient.PreKeyRecord;

  private constructor(handle: SignalClient.PreKeyRecord) {
    this.nativeHandle = handle;
  }

  static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
    return new PreKeyRecord(
      SC.PreKeyRecord_New(
        id,
        pubKey._unsafeGetNativeHandle(),
        privKey._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): PreKeyRecord {
    return new PreKeyRecord(SC.PreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return SC.PreKeyRecord_GetId(this.nativeHandle);
  }

  privateKey(): PrivateKey {
    return PrivateKey.fromNativeHandle(
      SC.PreKeyRecord_GetPrivateKey(this.nativeHandle)
    );
  }

  publicKey(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PreKeyRecord_GetPublicKey(this.nativeHandle)
    );
  }

  serialize(): Buffer {
    return SC.PreKeyRecord_Serialize(this.nativeHandle);
  }
}

export class SignalMessage {
  private readonly nativeHandle: SignalClient.SignalMessage;

  private constructor(handle: SignalClient.SignalMessage) {
    this.nativeHandle = handle;
  }

  _unsafeGetNativeHandle(): SignalClient.SignalMessage {
    return this.nativeHandle;
  }

  static new(
    messageVersion: number,
    macKey: Buffer,
    senderRatchetKey: PublicKey,
    counter: number,
    previousCounter: number,
    ciphertext: Buffer,
    senderIdentityKey: PublicKey,
    receiverIdentityKey: PublicKey
  ): SignalMessage {
    return new SignalMessage(
      SC.SignalMessage_New(
        messageVersion,
        macKey,
        senderRatchetKey._unsafeGetNativeHandle(),
        counter,
        previousCounter,
        ciphertext,
        senderIdentityKey._unsafeGetNativeHandle(),
        receiverIdentityKey._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): SignalMessage {
    return new SignalMessage(SC.SignalMessage_Deserialize(buffer));
  }

  body(): Buffer {
    return SC.SignalMessage_GetBody(this.nativeHandle);
  }

  counter(): number {
    return SC.SignalMessage_GetCounter(this.nativeHandle);
  }

  messageVersion(): number {
    return SC.SignalMessage_GetMessageVersion(this.nativeHandle);
  }

  serialize(): Buffer {
    return SC.SignalMessage_GetSerialized(this.nativeHandle);
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    recevierIdentityKey: PublicKey,
    macKey: Buffer
  ): boolean {
    return SC.SignalMessage_VerifyMac(
      this.nativeHandle,
      senderIdentityKey._unsafeGetNativeHandle(),
      recevierIdentityKey._unsafeGetNativeHandle(),
      macKey
    );
  }
}

export class PreKeySignalMessage {
  private readonly nativeHandle: SignalClient.PreKeySignalMessage;

  private constructor(handle: SignalClient.PreKeySignalMessage) {
    this.nativeHandle = handle;
  }

  static new(
    messageVersion: number,
    registrationId: number,
    preKeyId: number | null,
    signedPreKeyId: number,
    baseKey: PublicKey,
    identityKey: PublicKey,
    signalMessage: SignalMessage
  ): PreKeySignalMessage {
    return new PreKeySignalMessage(
      SC.PreKeySignalMessage_New(
        messageVersion,
        registrationId,
        preKeyId,
        signedPreKeyId,
        baseKey._unsafeGetNativeHandle(),
        identityKey._unsafeGetNativeHandle(),
        signalMessage._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): PreKeySignalMessage {
    return new PreKeySignalMessage(SC.PreKeySignalMessage_Deserialize(buffer));
  }

  preKeyId(): number | null {
    return SC.PreKeySignalMessage_GetPreKeyId(this.nativeHandle);
  }

  registrationId(): number {
    return SC.PreKeySignalMessage_GetRegistrationId(this.nativeHandle);
  }

  signedPreKeyId(): number {
    return SC.PreKeySignalMessage_GetSignedPreKeyId(this.nativeHandle);
  }

  version(): number {
    return SC.PreKeySignalMessage_GetVersion(this.nativeHandle);
  }

  serialize(): Buffer {
    return SC.PreKeySignalMessage_Serialize(this.nativeHandle);
  }
}
