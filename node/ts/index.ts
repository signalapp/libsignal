//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

import * as Errors from './Errors';
export * from './Errors';

import { Aci, ProtocolAddress, ServiceId } from './Address';
export * from './Address';
import { PrivateKey, PublicKey } from './EcKeys';
export * from './EcKeys';

export * as usernames from './usernames';

export * as io from './io';

export * as Net from './net';

export * as Mp4Sanitizer from './Mp4Sanitizer';
export * as WebpSanitizer from './WebpSanitizer';

import * as Native from '../Native';

Native.registerErrors(Errors);

// These enums must be kept in sync with their Rust counterparts.

export enum CiphertextMessageType {
  Whisper = 2,
  PreKey = 3,
  SenderKey = 7,
  Plaintext = 8,
}

export enum Direction {
  Sending,
  Receiving,
}

// This enum must be kept in sync with sealed_sender.proto.
export enum ContentHint {
  Default = 0,
  Resendable = 1,
  Implicit = 2,
}

export enum UsePQRatchet {
  Yes,
  No,
}

export type Uuid = string;

export function hkdf(
  outputLength: number,
  keyMaterial: Uint8Array,
  label: Uint8Array,
  salt: Uint8Array | null
): Uint8Array {
  return Native.HKDF_DeriveSecrets(outputLength, keyMaterial, label, salt);
}

export class ScannableFingerprint {
  private readonly scannable: Uint8Array;

  private constructor(scannable: Uint8Array) {
    this.scannable = scannable;
  }

  static _fromBuffer(scannable: Uint8Array): ScannableFingerprint {
    return new ScannableFingerprint(scannable);
  }

  compare(other: ScannableFingerprint): boolean {
    return Native.ScannableFingerprint_Compare(this.scannable, other.scannable);
  }

  toBuffer(): Uint8Array {
    return this.scannable;
  }
}

export class DisplayableFingerprint {
  private readonly display: string;

  private constructor(display: string) {
    this.display = display;
  }

  static _fromString(display: string): DisplayableFingerprint {
    return new DisplayableFingerprint(display);
  }

  toString(): string {
    return this.display;
  }
}

export class Fingerprint {
  readonly _nativeHandle: Native.Fingerprint;

  private constructor(nativeHandle: Native.Fingerprint) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    iterations: number,
    version: number,
    localIdentifier: Uint8Array,
    localKey: PublicKey,
    remoteIdentifier: Uint8Array,
    remoteKey: PublicKey
  ): Fingerprint {
    return new Fingerprint(
      Native.Fingerprint_New(
        iterations,
        version,
        localIdentifier,
        localKey,
        remoteIdentifier,
        remoteKey
      )
    );
  }

  public displayableFingerprint(): DisplayableFingerprint {
    return DisplayableFingerprint._fromString(
      Native.Fingerprint_DisplayString(this)
    );
  }

  public scannableFingerprint(): ScannableFingerprint {
    return ScannableFingerprint._fromBuffer(
      Native.Fingerprint_ScannableEncoding(this)
    );
  }
}

export class Aes256GcmSiv {
  readonly _nativeHandle: Native.Aes256GcmSiv;

  private constructor(key: Uint8Array) {
    this._nativeHandle = Native.Aes256GcmSiv_New(key);
  }

  static new(key: Uint8Array): Aes256GcmSiv {
    return new Aes256GcmSiv(key);
  }

  encrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    associated_data: Uint8Array
  ): Uint8Array {
    return Native.Aes256GcmSiv_Encrypt(this, message, nonce, associated_data);
  }

  decrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    associated_data: Uint8Array
  ): Uint8Array {
    return Native.Aes256GcmSiv_Decrypt(this, message, nonce, associated_data);
  }
}

export class KEMPublicKey {
  readonly _nativeHandle: Native.KyberPublicKey;

  private constructor(handle: Native.KyberPublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberPublicKey): KEMPublicKey {
    return new KEMPublicKey(handle);
  }

  static deserialize(buf: Uint8Array): KEMPublicKey {
    return new KEMPublicKey(Native.KyberPublicKey_Deserialize(buf));
  }

  serialize(): Uint8Array {
    return Native.KyberPublicKey_Serialize(this);
  }
}

export class KEMSecretKey {
  readonly _nativeHandle: Native.KyberSecretKey;

  private constructor(handle: Native.KyberSecretKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberSecretKey): KEMSecretKey {
    return new KEMSecretKey(handle);
  }

  static deserialize(buf: Uint8Array): KEMSecretKey {
    return new KEMSecretKey(Native.KyberSecretKey_Deserialize(buf));
  }

  serialize(): Uint8Array {
    return Native.KyberSecretKey_Serialize(this);
  }
}

export class KEMKeyPair {
  readonly _nativeHandle: Native.KyberKeyPair;

  private constructor(handle: Native.KyberKeyPair) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberKeyPair): KEMKeyPair {
    return new KEMKeyPair(handle);
  }

  static generate(): KEMKeyPair {
    return new KEMKeyPair(Native.KyberKeyPair_Generate());
  }

  getPublicKey(): KEMPublicKey {
    return KEMPublicKey._fromNativeHandle(
      Native.KyberKeyPair_GetPublicKey(this)
    );
  }

  getSecretKey(): KEMSecretKey {
    return KEMSecretKey._fromNativeHandle(
      Native.KyberKeyPair_GetSecretKey(this)
    );
  }
}

/** The public information contained in a {@link SignedPreKeyRecord} */
export type SignedPublicPreKey = {
  id(): number;
  publicKey(): PublicKey;
  signature(): Uint8Array;
};

/** The public information contained in a {@link KyberPreKeyRecord} */
export type SignedKyberPublicPreKey = {
  id(): number;
  publicKey(): KEMPublicKey;
  signature(): Uint8Array;
};

export class PreKeyBundle {
  readonly _nativeHandle: Native.PreKeyBundle;

  private constructor(handle: Native.PreKeyBundle) {
    this._nativeHandle = handle;
  }

  static new(
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: PublicKey | null,
    signed_prekey_id: number,
    signed_prekey: PublicKey,
    signed_prekey_signature: Uint8Array,
    identity_key: PublicKey,
    kyber_prekey_id: number,
    kyber_prekey: KEMPublicKey,
    kyber_prekey_signature: Uint8Array
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
  signedPreKeySignature(): Uint8Array {
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

  kyberPreKeySignature(): Uint8Array {
    return Native.PreKeyBundle_GetKyberPreKeySignature(this);
  }
}

export class PreKeyRecord {
  readonly _nativeHandle: Native.PreKeyRecord;

  private constructor(handle: Native.PreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(nativeHandle: Native.PreKeyRecord): PreKeyRecord {
    return new PreKeyRecord(nativeHandle);
  }

  static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
    return new PreKeyRecord(Native.PreKeyRecord_New(id, pubKey, privKey));
  }

  static deserialize(buffer: Uint8Array): PreKeyRecord {
    return new PreKeyRecord(Native.PreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return Native.PreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      Native.PreKeyRecord_GetPrivateKey(this)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(Native.PreKeyRecord_GetPublicKey(this));
  }

  serialize(): Uint8Array {
    return Native.PreKeyRecord_Serialize(this);
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
    signature: Uint8Array
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      Native.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature)
    );
  }

  static deserialize(buffer: Uint8Array): SignedPreKeyRecord {
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

  serialize(): Uint8Array {
    return Native.SignedPreKeyRecord_Serialize(this);
  }

  signature(): Uint8Array {
    return Native.SignedPreKeyRecord_GetSignature(this);
  }

  timestamp(): number {
    return Native.SignedPreKeyRecord_GetTimestamp(this);
  }
}

export class KyberPreKeyRecord implements SignedKyberPublicPreKey {
  readonly _nativeHandle: Native.KyberPreKeyRecord;

  private constructor(handle: Native.KyberPreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.KyberPreKeyRecord
  ): KyberPreKeyRecord {
    return new KyberPreKeyRecord(nativeHandle);
  }

  static new(
    id: number,
    timestamp: number,
    keyPair: KEMKeyPair,
    signature: Uint8Array
  ): KyberPreKeyRecord {
    return new KyberPreKeyRecord(
      Native.KyberPreKeyRecord_New(id, timestamp, keyPair, signature)
    );
  }

  serialize(): Uint8Array {
    return Native.KyberPreKeyRecord_Serialize(this);
  }

  static deserialize(buffer: Uint8Array): KyberPreKeyRecord {
    return new KyberPreKeyRecord(Native.KyberPreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return Native.KyberPreKeyRecord_GetId(this);
  }

  keyPair(): KEMKeyPair {
    return KEMKeyPair._fromNativeHandle(
      Native.KyberPreKeyRecord_GetKeyPair(this)
    );
  }

  publicKey(): KEMPublicKey {
    return KEMPublicKey._fromNativeHandle(
      Native.KyberPreKeyRecord_GetPublicKey(this)
    );
  }

  secretKey(): KEMSecretKey {
    return KEMSecretKey._fromNativeHandle(
      Native.KyberPreKeyRecord_GetSecretKey(this)
    );
  }

  signature(): Uint8Array {
    return Native.KyberPreKeyRecord_GetSignature(this);
  }

  timestamp(): number {
    return Native.KyberPreKeyRecord_GetTimestamp(this);
  }
}

export class SignalMessage {
  readonly _nativeHandle: Native.SignalMessage;

  private constructor(handle: Native.SignalMessage) {
    this._nativeHandle = handle;
  }

  static _new(
    messageVersion: number,
    macKey: Uint8Array,
    senderRatchetKey: PublicKey,
    counter: number,
    previousCounter: number,
    ciphertext: Uint8Array,
    senderIdentityKey: PublicKey,
    receiverIdentityKey: PublicKey,
    pqRatchet: Uint8Array
  ): SignalMessage {
    return new SignalMessage(
      Native.SignalMessage_New(
        messageVersion,
        macKey,
        senderRatchetKey,
        counter,
        previousCounter,
        ciphertext,
        senderIdentityKey,
        receiverIdentityKey,
        pqRatchet
      )
    );
  }

  static deserialize(buffer: Uint8Array): SignalMessage {
    return new SignalMessage(Native.SignalMessage_Deserialize(buffer));
  }

  body(): Uint8Array {
    return Native.SignalMessage_GetBody(this);
  }

  pqRatchet(): Uint8Array {
    return Native.SignalMessage_GetPqRatchet(this);
  }

  counter(): number {
    return Native.SignalMessage_GetCounter(this);
  }

  messageVersion(): number {
    return Native.SignalMessage_GetMessageVersion(this);
  }

  serialize(): Uint8Array {
    return Native.SignalMessage_GetSerialized(this);
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    recevierIdentityKey: PublicKey,
    macKey: Uint8Array
  ): boolean {
    return Native.SignalMessage_VerifyMac(
      this,
      senderIdentityKey,
      recevierIdentityKey,
      macKey
    );
  }
}

export class PreKeySignalMessage {
  readonly _nativeHandle: Native.PreKeySignalMessage;

  private constructor(handle: Native.PreKeySignalMessage) {
    this._nativeHandle = handle;
  }

  static _new(
    messageVersion: number,
    registrationId: number,
    preKeyId: number | null,
    signedPreKeyId: number,
    baseKey: PublicKey,
    identityKey: PublicKey,
    signalMessage: SignalMessage
  ): PreKeySignalMessage {
    return new PreKeySignalMessage(
      Native.PreKeySignalMessage_New(
        messageVersion,
        registrationId,
        preKeyId,
        signedPreKeyId,
        baseKey,
        identityKey,
        signalMessage
      )
    );
  }

  static deserialize(buffer: Uint8Array): PreKeySignalMessage {
    return new PreKeySignalMessage(
      Native.PreKeySignalMessage_Deserialize(buffer)
    );
  }

  preKeyId(): number | null {
    return Native.PreKeySignalMessage_GetPreKeyId(this);
  }

  registrationId(): number {
    return Native.PreKeySignalMessage_GetRegistrationId(this);
  }

  signedPreKeyId(): number {
    return Native.PreKeySignalMessage_GetSignedPreKeyId(this);
  }

  version(): number {
    return Native.PreKeySignalMessage_GetVersion(this);
  }

  serialize(): Uint8Array {
    return Native.PreKeySignalMessage_Serialize(this);
  }
}

export class SessionRecord {
  readonly _nativeHandle: Native.SessionRecord;

  private constructor(nativeHandle: Native.SessionRecord) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(nativeHandle: Native.SessionRecord): SessionRecord {
    return new SessionRecord(nativeHandle);
  }

  static deserialize(buffer: Uint8Array): SessionRecord {
    return new SessionRecord(Native.SessionRecord_Deserialize(buffer));
  }

  serialize(): Uint8Array {
    return Native.SessionRecord_Serialize(this);
  }

  archiveCurrentState(): void {
    Native.SessionRecord_ArchiveCurrentState(this);
  }

  localRegistrationId(): number {
    return Native.SessionRecord_GetLocalRegistrationId(this);
  }

  remoteRegistrationId(): number {
    return Native.SessionRecord_GetRemoteRegistrationId(this);
  }

  /**
   * Returns whether the current session can be used to send messages.
   *
   * If there is no current session, returns false.
   */
  hasCurrentState(now: Date = new Date()): boolean {
    return Native.SessionRecord_HasUsableSenderChain(this, now.getTime());
  }

  currentRatchetKeyMatches(key: PublicKey): boolean {
    return Native.SessionRecord_CurrentRatchetKeyMatches(this, key);
  }
}

export class ServerCertificate {
  readonly _nativeHandle: Native.ServerCertificate;

  static _fromNativeHandle(
    nativeHandle: Native.ServerCertificate
  ): ServerCertificate {
    return new ServerCertificate(nativeHandle);
  }

  private constructor(nativeHandle: Native.ServerCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    serverKey: PublicKey,
    trustRoot: PrivateKey
  ): ServerCertificate {
    return new ServerCertificate(
      Native.ServerCertificate_New(keyId, serverKey, trustRoot)
    );
  }

  static deserialize(buffer: Uint8Array): ServerCertificate {
    return new ServerCertificate(Native.ServerCertificate_Deserialize(buffer));
  }

  certificateData(): Uint8Array {
    return Native.ServerCertificate_GetCertificate(this);
  }

  key(): PublicKey {
    return PublicKey._fromNativeHandle(Native.ServerCertificate_GetKey(this));
  }

  keyId(): number {
    return Native.ServerCertificate_GetKeyId(this);
  }

  serialize(): Uint8Array {
    return Native.ServerCertificate_GetSerialized(this);
  }

  signature(): Uint8Array {
    return Native.ServerCertificate_GetSignature(this);
  }
}

export class SenderKeyRecord {
  readonly _nativeHandle: Native.SenderKeyRecord;

  static _fromNativeHandle(
    nativeHandle: Native.SenderKeyRecord
  ): SenderKeyRecord {
    return new SenderKeyRecord(nativeHandle);
  }

  private constructor(nativeHandle: Native.SenderKeyRecord) {
    this._nativeHandle = nativeHandle;
  }

  static deserialize(buffer: Uint8Array): SenderKeyRecord {
    return new SenderKeyRecord(Native.SenderKeyRecord_Deserialize(buffer));
  }

  serialize(): Uint8Array {
    return Native.SenderKeyRecord_Serialize(this);
  }
}

export class SenderCertificate {
  readonly _nativeHandle: Native.SenderCertificate;

  private constructor(nativeHandle: Native.SenderCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SenderCertificate
  ): SenderCertificate {
    return new SenderCertificate(nativeHandle);
  }

  static new(
    senderUuid: string | Aci,
    senderE164: string | null,
    senderDeviceId: number,
    senderKey: PublicKey,
    expiration: number,
    signerCert: ServerCertificate,
    signerKey: PrivateKey
  ): SenderCertificate {
    if (typeof senderUuid !== 'string') {
      senderUuid = senderUuid.getServiceIdString();
    }
    return new SenderCertificate(
      Native.SenderCertificate_New(
        senderUuid,
        senderE164,
        senderDeviceId,
        senderKey,
        expiration,
        signerCert,
        signerKey
      )
    );
  }

  static deserialize(buffer: Uint8Array): SenderCertificate {
    return new SenderCertificate(Native.SenderCertificate_Deserialize(buffer));
  }

  serialize(): Uint8Array {
    return Native.SenderCertificate_GetSerialized(this);
  }

  certificate(): Uint8Array {
    return Native.SenderCertificate_GetCertificate(this);
  }
  expiration(): number {
    return Native.SenderCertificate_GetExpiration(this);
  }
  key(): PublicKey {
    return PublicKey._fromNativeHandle(Native.SenderCertificate_GetKey(this));
  }
  senderE164(): string | null {
    return Native.SenderCertificate_GetSenderE164(this);
  }
  senderUuid(): string {
    return Native.SenderCertificate_GetSenderUuid(this);
  }
  /**
   * Returns an ACI if the sender is a valid UUID, `null` otherwise.
   *
   * In a future release SenderCertificate will *only* support ACIs.
   */
  senderAci(): Aci | null {
    try {
      return Aci.parseFromServiceIdString(this.senderUuid());
    } catch {
      return null;
    }
  }
  senderDeviceId(): number {
    return Native.SenderCertificate_GetDeviceId(this);
  }
  serverCertificate(): ServerCertificate {
    return ServerCertificate._fromNativeHandle(
      Native.SenderCertificate_GetServerCertificate(this)
    );
  }
  signature(): Uint8Array {
    return Native.SenderCertificate_GetSignature(this);
  }
  validate(trustRoot: PublicKey, time: number): boolean {
    return Native.SenderCertificate_Validate(this, trustRoot, time);
  }
}

export class SenderKeyDistributionMessage {
  readonly _nativeHandle: Native.SenderKeyDistributionMessage;

  private constructor(nativeHandle: Native.SenderKeyDistributionMessage) {
    this._nativeHandle = nativeHandle;
  }

  static async create(
    sender: ProtocolAddress,
    distributionId: Uuid,
    store: SenderKeyStore
  ): Promise<SenderKeyDistributionMessage> {
    const handle = await Native.SenderKeyDistributionMessage_Create(
      sender,
      uuid.parse(distributionId),
      store
    );
    return new SenderKeyDistributionMessage(handle);
  }

  static _new(
    messageVersion: number,
    distributionId: Uuid,
    chainId: number,
    iteration: number,
    chainKey: Uint8Array,
    pk: PublicKey
  ): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      Native.SenderKeyDistributionMessage_New(
        messageVersion,
        uuid.parse(distributionId),
        chainId,
        iteration,
        chainKey,
        pk
      )
    );
  }

  static deserialize(buffer: Uint8Array): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      Native.SenderKeyDistributionMessage_Deserialize(buffer)
    );
  }

  serialize(): Uint8Array {
    return Native.SenderKeyDistributionMessage_Serialize(this);
  }

  chainKey(): Uint8Array {
    return Native.SenderKeyDistributionMessage_GetChainKey(this);
  }

  iteration(): number {
    return Native.SenderKeyDistributionMessage_GetIteration(this);
  }

  chainId(): number {
    return Native.SenderKeyDistributionMessage_GetChainId(this);
  }

  distributionId(): Uuid {
    return uuid.stringify(
      Native.SenderKeyDistributionMessage_GetDistributionId(this)
    );
  }
}

export async function processSenderKeyDistributionMessage(
  sender: ProtocolAddress,
  message: SenderKeyDistributionMessage,
  store: SenderKeyStore
): Promise<void> {
  await Native.SenderKeyDistributionMessage_Process(sender, message, store);
}

export class SenderKeyMessage {
  readonly _nativeHandle: Native.SenderKeyMessage;

  private constructor(nativeHandle: Native.SenderKeyMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _new(
    messageVersion: number,
    distributionId: Uuid,
    chainId: number,
    iteration: number,
    ciphertext: Uint8Array,
    pk: PrivateKey
  ): SenderKeyMessage {
    return new SenderKeyMessage(
      Native.SenderKeyMessage_New(
        messageVersion,
        uuid.parse(distributionId),
        chainId,
        iteration,
        ciphertext,
        pk
      )
    );
  }

  static deserialize(buffer: Uint8Array): SenderKeyMessage {
    return new SenderKeyMessage(Native.SenderKeyMessage_Deserialize(buffer));
  }

  serialize(): Uint8Array {
    return Native.SenderKeyMessage_Serialize(this);
  }

  ciphertext(): Uint8Array {
    return Native.SenderKeyMessage_GetCipherText(this);
  }

  iteration(): number {
    return Native.SenderKeyMessage_GetIteration(this);
  }

  chainId(): number {
    return Native.SenderKeyMessage_GetChainId(this);
  }

  distributionId(): Uuid {
    return uuid.stringify(Native.SenderKeyMessage_GetDistributionId(this));
  }

  verifySignature(key: PublicKey): boolean {
    return Native.SenderKeyMessage_VerifySignature(this, key);
  }
}

export class UnidentifiedSenderMessageContent {
  readonly _nativeHandle: Native.UnidentifiedSenderMessageContent;

  private constructor(nativeHandle: Native.UnidentifiedSenderMessageContent) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.UnidentifiedSenderMessageContent
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(nativeHandle);
  }

  static new(
    message: CiphertextMessage,
    sender: SenderCertificate,
    contentHint: number,
    groupId: Uint8Array | null
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      Native.UnidentifiedSenderMessageContent_New(
        message,
        sender,
        contentHint,
        groupId
      )
    );
  }

  static deserialize(buffer: Uint8Array): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      Native.UnidentifiedSenderMessageContent_Deserialize(buffer)
    );
  }

  serialize(): Uint8Array {
    return Native.UnidentifiedSenderMessageContent_Serialize(this);
  }

  contents(): Uint8Array {
    return Native.UnidentifiedSenderMessageContent_GetContents(this);
  }

  msgType(): number {
    return Native.UnidentifiedSenderMessageContent_GetMsgType(this);
  }

  senderCertificate(): SenderCertificate {
    return SenderCertificate._fromNativeHandle(
      Native.UnidentifiedSenderMessageContent_GetSenderCert(this)
    );
  }

  contentHint(): number {
    return Native.UnidentifiedSenderMessageContent_GetContentHint(this);
  }

  groupId(): Uint8Array | null {
    return Native.UnidentifiedSenderMessageContent_GetGroupId(this);
  }
}

export abstract class SessionStore implements Native.SessionStore {
  async _saveSession(
    name: Native.ProtocolAddress,
    record: Native.SessionRecord
  ): Promise<void> {
    return this.saveSession(
      ProtocolAddress._fromNativeHandle(name),
      SessionRecord._fromNativeHandle(record)
    );
  }
  async _getSession(
    name: Native.ProtocolAddress
  ): Promise<Native.SessionRecord | null> {
    const sess = await this.getSession(ProtocolAddress._fromNativeHandle(name));
    if (sess == null) {
      return null;
    } else {
      return sess._nativeHandle;
    }
  }

  abstract saveSession(
    name: ProtocolAddress,
    record: SessionRecord
  ): Promise<void>;
  abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>;
  abstract getExistingSessions(
    addresses: ProtocolAddress[]
  ): Promise<SessionRecord[]>;
}

export enum IdentityChange {
  // This must be kept in sync with the Rust enum of the same name.
  NewOrUnchanged = 0,
  ReplacedExisting = 1,
}

export abstract class IdentityKeyStore implements Native.IdentityKeyStore {
  async _getIdentityKey(): Promise<Native.PrivateKey> {
    const key = await this.getIdentityKey();
    return key._nativeHandle;
  }

  async _getLocalRegistrationId(): Promise<number> {
    return this.getLocalRegistrationId();
  }
  async _saveIdentity(
    name: Native.ProtocolAddress,
    key: Native.PublicKey
  ): Promise<Native.IdentityChange> {
    return this.saveIdentity(
      ProtocolAddress._fromNativeHandle(name),
      PublicKey._fromNativeHandle(key)
    );
  }
  async _isTrustedIdentity(
    name: Native.ProtocolAddress,
    key: Native.PublicKey,
    sending: boolean
  ): Promise<boolean> {
    const direction = sending ? Direction.Sending : Direction.Receiving;

    return this.isTrustedIdentity(
      ProtocolAddress._fromNativeHandle(name),
      PublicKey._fromNativeHandle(key),
      direction
    );
  }
  async _getIdentity(
    name: Native.ProtocolAddress
  ): Promise<Native.PublicKey | null> {
    const key = await this.getIdentity(ProtocolAddress._fromNativeHandle(name));
    if (key == null) {
      return Promise.resolve(null);
    } else {
      return key._nativeHandle;
    }
  }

  abstract getIdentityKey(): Promise<PrivateKey>;
  abstract getLocalRegistrationId(): Promise<number>;
  abstract saveIdentity(
    name: ProtocolAddress,
    key: PublicKey
  ): Promise<IdentityChange>;
  abstract isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    direction: Direction
  ): Promise<boolean>;
  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class PreKeyStore implements Native.PreKeyStore {
  async _savePreKey(id: number, record: Native.PreKeyRecord): Promise<void> {
    return this.savePreKey(id, PreKeyRecord._fromNativeHandle(record));
  }
  async _getPreKey(id: number): Promise<Native.PreKeyRecord> {
    const pk = await this.getPreKey(id);
    return pk._nativeHandle;
  }
  async _removePreKey(id: number): Promise<void> {
    return this.removePreKey(id);
  }

  abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>;
  abstract getPreKey(id: number): Promise<PreKeyRecord>;
  abstract removePreKey(id: number): Promise<void>;
}

export abstract class SignedPreKeyStore implements Native.SignedPreKeyStore {
  async _saveSignedPreKey(
    id: number,
    record: Native.SignedPreKeyRecord
  ): Promise<void> {
    return this.saveSignedPreKey(
      id,
      SignedPreKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSignedPreKey(id: number): Promise<Native.SignedPreKeyRecord> {
    const pk = await this.getSignedPreKey(id);
    return pk._nativeHandle;
  }

  abstract saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord
  ): Promise<void>;
  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}

export abstract class KyberPreKeyStore implements Native.KyberPreKeyStore {
  async _saveKyberPreKey(
    kyberPreKeyId: number,
    record: Native.KyberPreKeyRecord
  ): Promise<void> {
    return this.saveKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord._fromNativeHandle(record)
    );
  }
  async _getKyberPreKey(
    kyberPreKeyId: number
  ): Promise<Native.KyberPreKeyRecord> {
    const prekey = await this.getKyberPreKey(kyberPreKeyId);
    return prekey._nativeHandle;
  }

  async _markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void> {
    return this.markKyberPreKeyUsed(kyberPreKeyId);
  }

  abstract saveKyberPreKey(
    kyberPreKeyId: number,
    record: KyberPreKeyRecord
  ): Promise<void>;
  abstract getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;
  abstract markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void>;
}

export abstract class SenderKeyStore implements Native.SenderKeyStore {
  async _saveSenderKey(
    sender: Native.ProtocolAddress,
    distributionId: Native.Uuid,
    record: Native.SenderKeyRecord
  ): Promise<void> {
    return this.saveSenderKey(
      ProtocolAddress._fromNativeHandle(sender),
      uuid.stringify(distributionId),
      SenderKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSenderKey(
    sender: Native.ProtocolAddress,
    distributionId: Native.Uuid
  ): Promise<Native.SenderKeyRecord | null> {
    const skr = await this.getSenderKey(
      ProtocolAddress._fromNativeHandle(sender),
      uuid.stringify(distributionId)
    );
    if (skr == null) {
      return null;
    } else {
      return skr._nativeHandle;
    }
  }

  abstract saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord
  ): Promise<void>;
  abstract getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid
  ): Promise<SenderKeyRecord | null>;
}

export async function groupEncrypt(
  sender: ProtocolAddress,
  distributionId: Uuid,
  store: SenderKeyStore,
  message: Uint8Array
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await Native.GroupCipher_EncryptMessage(
      sender,
      uuid.parse(distributionId),
      message,
      store
    )
  );
}

export async function groupDecrypt(
  sender: ProtocolAddress,
  store: SenderKeyStore,
  message: Uint8Array
): Promise<Uint8Array> {
  return Native.GroupCipher_DecryptMessage(sender, message, store);
}

export class SealedSenderDecryptionResult {
  readonly _nativeHandle: Native.SealedSenderDecryptionResult;

  private constructor(nativeHandle: Native.SealedSenderDecryptionResult) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SealedSenderDecryptionResult
  ): SealedSenderDecryptionResult {
    return new SealedSenderDecryptionResult(nativeHandle);
  }

  message(): Uint8Array {
    return Native.SealedSenderDecryptionResult_Message(this);
  }

  senderE164(): string | null {
    return Native.SealedSenderDecryptionResult_GetSenderE164(this);
  }

  senderUuid(): string {
    return Native.SealedSenderDecryptionResult_GetSenderUuid(this);
  }

  /**
   * Returns an ACI if the sender is a valid UUID, `null` otherwise.
   *
   * In a future release SenderCertificate will *only* support ACIs.
   */
  senderAci(): Aci | null {
    try {
      return Aci.parseFromServiceIdString(this.senderUuid());
    } catch {
      return null;
    }
  }

  deviceId(): number {
    return Native.SealedSenderDecryptionResult_GetDeviceId(this);
  }
}

export interface CiphertextMessageConvertible {
  asCiphertextMessage(): CiphertextMessage;
}

export class CiphertextMessage {
  readonly _nativeHandle: Native.CiphertextMessage;

  private constructor(nativeHandle: Native.CiphertextMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.CiphertextMessage
  ): CiphertextMessage {
    return new CiphertextMessage(nativeHandle);
  }

  static from(message: CiphertextMessageConvertible): CiphertextMessage {
    return message.asCiphertextMessage();
  }

  serialize(): Uint8Array {
    return Native.CiphertextMessage_Serialize(this);
  }

  type(): number {
    return Native.CiphertextMessage_Type(this);
  }
}

export class PlaintextContent implements CiphertextMessageConvertible {
  readonly _nativeHandle: Native.PlaintextContent;

  private constructor(nativeHandle: Native.PlaintextContent) {
    this._nativeHandle = nativeHandle;
  }

  static deserialize(buffer: Uint8Array): PlaintextContent {
    return new PlaintextContent(Native.PlaintextContent_Deserialize(buffer));
  }

  static from(message: DecryptionErrorMessage): PlaintextContent {
    return new PlaintextContent(
      Native.PlaintextContent_FromDecryptionErrorMessage(message)
    );
  }

  serialize(): Uint8Array {
    return Native.PlaintextContent_Serialize(this);
  }

  body(): Uint8Array {
    return Native.PlaintextContent_GetBody(this);
  }

  asCiphertextMessage(): CiphertextMessage {
    return CiphertextMessage._fromNativeHandle(
      Native.CiphertextMessage_FromPlaintextContent(this)
    );
  }
}

export class DecryptionErrorMessage {
  readonly _nativeHandle: Native.DecryptionErrorMessage;

  private constructor(nativeHandle: Native.DecryptionErrorMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.DecryptionErrorMessage
  ): DecryptionErrorMessage {
    return new DecryptionErrorMessage(nativeHandle);
  }

  static forOriginal(
    bytes: Uint8Array,
    type: CiphertextMessageType,
    timestamp: number,
    originalSenderDeviceId: number
  ): DecryptionErrorMessage {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ForOriginalMessage(
        bytes,
        type,
        timestamp,
        originalSenderDeviceId
      )
    );
  }

  static deserialize(buffer: Uint8Array): DecryptionErrorMessage {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_Deserialize(buffer)
    );
  }

  static extractFromSerializedBody(buffer: Uint8Array): DecryptionErrorMessage {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ExtractFromSerializedContent(buffer)
    );
  }

  serialize(): Uint8Array {
    return Native.DecryptionErrorMessage_Serialize(this);
  }

  timestamp(): number {
    return Native.DecryptionErrorMessage_GetTimestamp(this);
  }

  deviceId(): number {
    return Native.DecryptionErrorMessage_GetDeviceId(this);
  }

  ratchetKey(): PublicKey | undefined {
    const keyHandle = Native.DecryptionErrorMessage_GetRatchetKey(this);
    if (keyHandle) {
      return PublicKey._fromNativeHandle(keyHandle);
    } else {
      return undefined;
    }
  }
}

export function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  usePqRatchet: UsePQRatchet,
  now: Date = new Date()
): Promise<void> {
  return Native.SessionBuilder_ProcessPreKeyBundle(
    bundle,
    address,
    sessionStore,
    identityStore,
    now.getTime(),
    usePqRatchet == UsePQRatchet.Yes
  );
}

export async function signalEncrypt(
  message: Uint8Array,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  now: Date = new Date()
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await Native.SessionCipher_EncryptMessage(
      message,
      address,
      sessionStore,
      identityStore,
      now.getTime()
    )
  );
}

export function signalDecrypt(
  message: SignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Uint8Array> {
  return Native.SessionCipher_DecryptSignalMessage(
    message,
    address,
    sessionStore,
    identityStore
  );
}

export function signalDecryptPreKey(
  message: PreKeySignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore,
  kyberPrekeyStore: KyberPreKeyStore,
  usePqRatchet: UsePQRatchet
): Promise<Uint8Array> {
  return Native.SessionCipher_DecryptPreKeySignalMessage(
    message,
    address,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore,
    kyberPrekeyStore,
    usePqRatchet == UsePQRatchet.Yes
  );
}

export async function sealedSenderEncryptMessage(
  message: Uint8Array,
  address: ProtocolAddress,
  senderCert: SenderCertificate,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Uint8Array> {
  const ciphertext = await signalEncrypt(
    message,
    address,
    sessionStore,
    identityStore
  );
  const usmc = UnidentifiedSenderMessageContent.new(
    ciphertext,
    senderCert,
    ContentHint.Default,
    null
  );
  return await sealedSenderEncrypt(usmc, address, identityStore);
}

export function sealedSenderEncrypt(
  content: UnidentifiedSenderMessageContent,
  address: ProtocolAddress,
  identityStore: IdentityKeyStore
): Promise<Uint8Array> {
  return Native.SealedSender_Encrypt(address, content, identityStore);
}

export type SealedSenderMultiRecipientEncryptOptions = {
  content: UnidentifiedSenderMessageContent;
  recipients: ProtocolAddress[];
  excludedRecipients?: ServiceId[];
  identityStore: IdentityKeyStore;
  sessionStore: SessionStore;
};

export async function sealedSenderMultiRecipientEncrypt(
  options: SealedSenderMultiRecipientEncryptOptions
): Promise<Uint8Array>;
export async function sealedSenderMultiRecipientEncrypt(
  content: UnidentifiedSenderMessageContent,
  recipients: ProtocolAddress[],
  identityStore: IdentityKeyStore,
  sessionStore: SessionStore
): Promise<Uint8Array>;

export async function sealedSenderMultiRecipientEncrypt(
  contentOrOptions:
    | UnidentifiedSenderMessageContent
    | SealedSenderMultiRecipientEncryptOptions,
  recipients?: ProtocolAddress[],
  identityStore?: IdentityKeyStore,
  sessionStore?: SessionStore
): Promise<Uint8Array> {
  let excludedRecipients: ServiceId[] | undefined = undefined;
  if (contentOrOptions instanceof UnidentifiedSenderMessageContent) {
    if (!recipients || !identityStore || !sessionStore) {
      throw Error('missing arguments for sealedSenderMultiRecipientEncrypt');
    }
  } else {
    ({
      content: contentOrOptions,
      recipients,
      excludedRecipients,
      identityStore,
      sessionStore,
    } = contentOrOptions);
  }

  const recipientSessions = await sessionStore.getExistingSessions(recipients);
  return await Native.SealedSender_MultiRecipientEncrypt(
    recipients,
    recipientSessions,
    ServiceId.toConcatenatedFixedWidthBinary(excludedRecipients ?? []),
    contentOrOptions,
    identityStore
  );
}

// For testing only
export function sealedSenderMultiRecipientMessageForSingleRecipient(
  message: Uint8Array
): Uint8Array {
  return Native.SealedSender_MultiRecipientMessageForSingleRecipient(message);
}

export async function sealedSenderDecryptMessage(
  message: Uint8Array,
  trustRoot: PublicKey,
  timestamp: number,
  localE164: string | null,
  localUuid: string,
  localDeviceId: number,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore,
  kyberPrekeyStore: KyberPreKeyStore,
  usePqRatchet: UsePQRatchet
): Promise<SealedSenderDecryptionResult> {
  const ssdr = await Native.SealedSender_DecryptMessage(
    message,
    trustRoot,
    timestamp,
    localE164,
    localUuid,
    localDeviceId,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore,
    kyberPrekeyStore,
    usePqRatchet == UsePQRatchet.Yes
  );
  return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
}

export async function sealedSenderDecryptToUsmc(
  message: Uint8Array,
  identityStore: IdentityKeyStore
): Promise<UnidentifiedSenderMessageContent> {
  const usmc = await Native.SealedSender_DecryptToUsmc(message, identityStore);
  return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
}

export class Cds2Client {
  readonly _nativeHandle: Native.SgxClientState;

  private constructor(nativeHandle: Native.SgxClientState) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    mrenclave: Uint8Array,
    attestationMsg: Uint8Array,
    currentTimestamp: Date
  ): Cds2Client {
    return new Cds2Client(
      Native.Cds2ClientState_New(
        mrenclave,
        attestationMsg,
        currentTimestamp.getTime()
      )
    );
  }

  initialRequest(): Uint8Array {
    return Native.SgxClientState_InitialRequest(this);
  }

  completeHandshake(buffer: Uint8Array): void {
    return Native.SgxClientState_CompleteHandshake(this, buffer);
  }

  establishedSend(buffer: Uint8Array): Uint8Array {
    return Native.SgxClientState_EstablishedSend(this, buffer);
  }

  establishedRecv(buffer: Uint8Array): Uint8Array {
    return Native.SgxClientState_EstablishedRecv(this, buffer);
  }
}

export class HsmEnclaveClient {
  readonly _nativeHandle: Native.HsmEnclaveClient;

  private constructor(nativeHandle: Native.HsmEnclaveClient) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    public_key: Uint8Array,
    code_hashes: Uint8Array[]
  ): HsmEnclaveClient {
    code_hashes.forEach((hash) => {
      if (hash.length != 32) {
        throw new Error('code hash length must be 32');
      }
    });
    const concat_hashes = Buffer.concat(code_hashes);

    return new HsmEnclaveClient(
      Native.HsmEnclaveClient_New(public_key, concat_hashes)
    );
  }

  initialRequest(): Uint8Array {
    return Native.HsmEnclaveClient_InitialRequest(this);
  }

  completeHandshake(buffer: Uint8Array): void {
    return Native.HsmEnclaveClient_CompleteHandshake(this, buffer);
  }

  establishedSend(buffer: Uint8Array): Uint8Array {
    return Native.HsmEnclaveClient_EstablishedSend(this, buffer);
  }

  establishedRecv(buffer: Uint8Array): Uint8Array {
    return Native.HsmEnclaveClient_EstablishedRecv(this, buffer);
  }
}

export enum LogLevel {
  Error = 1,
  Warn,
  Info,
  Debug,
  Trace,
}

export function initLogger(
  maxLevel: LogLevel,
  callback: (
    level: LogLevel,
    target: string,
    file: string | null,
    line: number | null,
    message: string
  ) => void
): void {
  let nativeMaxLevel: Native.LogLevel;
  switch (maxLevel) {
    case LogLevel.Error:
      nativeMaxLevel = Native.LogLevel.Error;
      break;
    case LogLevel.Warn:
      nativeMaxLevel = Native.LogLevel.Warn;
      break;
    case LogLevel.Info:
      nativeMaxLevel = Native.LogLevel.Info;
      break;
    case LogLevel.Debug:
      nativeMaxLevel = Native.LogLevel.Debug;
      break;
    case LogLevel.Trace:
      nativeMaxLevel = Native.LogLevel.Trace;
      break;
  }
  Native.initLogger(
    nativeMaxLevel,
    (nativeLevel, target, file, line, message) => {
      let level: LogLevel;
      switch (nativeLevel) {
        case Native.LogLevel.Error:
          level = LogLevel.Error;
          break;
        case Native.LogLevel.Warn:
          level = LogLevel.Warn;
          break;
        case Native.LogLevel.Info:
          level = LogLevel.Info;
          break;
        case Native.LogLevel.Debug:
          level = LogLevel.Debug;
          break;
        case Native.LogLevel.Trace:
          level = LogLevel.Trace;
          break;
        default:
          callback(
            LogLevel.Warn,
            'signal-client',
            'index.ts',
            0,
            `unknown log level ${nativeLevel}; treating as error`
          );
          level = LogLevel.Error;
          break;
      }
      callback(level, target, file, line, message);
    }
  );
}
