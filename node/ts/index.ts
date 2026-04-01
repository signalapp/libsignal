//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { Buffer } from 'node:buffer';

import * as Errors from './Errors.js';
export * from './Errors.js';

import { Aci, ProtocolAddress, ServiceId } from './Address.js';
export * from './Address.js';
import { IdentityKeyPair, PrivateKey, PublicKey } from './EcKeys.js';
export * from './EcKeys.js';
import {
  KEMPublicKey,
  PreKeyBundle,
  SignedPreKeyRecord,
} from './ProtocolTypes.js';
export * from './ProtocolTypes.js';
import * as uuid from './uuid.js';

export * as usernames from './usernames.js';

export * as io from './io.js';

export * as Net from './net.js';

export * as Mp4Sanitizer from './Mp4Sanitizer.js';
export * as WebpSanitizer from './WebpSanitizer.js';

import * as Native from './Native.js';

Native.registerErrors(Errors);

export type Uuid = uuid.Uuid;

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

export function hkdf(
  outputLength: number,
  keyMaterial: Uint8Array<ArrayBuffer>,
  label: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer> | null
): Uint8Array<ArrayBuffer> {
  return Native.HKDF_DeriveSecrets(outputLength, keyMaterial, label, salt);
}

export class ScannableFingerprint {
  private readonly scannable: Uint8Array<ArrayBuffer>;

  private constructor(scannable: Uint8Array<ArrayBuffer>) {
    this.scannable = scannable;
  }

  static _fromBuffer(scannable: Uint8Array<ArrayBuffer>): ScannableFingerprint {
    return new ScannableFingerprint(scannable);
  }

  compare(other: ScannableFingerprint): boolean {
    return Native.ScannableFingerprint_Compare(this.scannable, other.scannable);
  }

  toBuffer(): Uint8Array<ArrayBuffer> {
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
    localIdentifier: Uint8Array<ArrayBuffer>,
    localKey: PublicKey,
    remoteIdentifier: Uint8Array<ArrayBuffer>,
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

/**
 * Implements the <a href="https://en.wikipedia.org/wiki/AES-GCM-SIV">AES-256-GCM-SIV</a>
 * authenticated stream cipher with a 12-byte nonce.
 *
 * AES-GCM-SIV is a multi-pass algorithm (to generate the "synthetic initialization vector"), so
 * this API does not expose a streaming form.
 */
export class Aes256GcmSiv {
  readonly _nativeHandle: Native.Aes256GcmSiv;

  private constructor(key: Uint8Array<ArrayBuffer>) {
    this._nativeHandle = Native.Aes256GcmSiv_New(key);
  }

  static new(key: Uint8Array<ArrayBuffer>): Aes256GcmSiv {
    return new Aes256GcmSiv(key);
  }

  /**
   * Encrypts the given plaintext using the given nonce, and authenticating the ciphertext and given
   * associated data.
   *
   * The associated data is not included in the ciphertext; instead, it's expected to match between
   * the encrypter and decrypter. If you don't need any extra data, pass an empty array.
   *
   * @returns The encrypted data, including an appended 16-byte authentication tag.
   */
  encrypt(
    message: Uint8Array<ArrayBuffer>,
    nonce: Uint8Array<ArrayBuffer>,
    associatedData: Uint8Array<ArrayBuffer>
  ): Uint8Array<ArrayBuffer> {
    return Native.Aes256GcmSiv_Encrypt(this, message, nonce, associatedData);
  }

  /**
   * Decrypts the given ciphertext using the given nonce, and authenticating the ciphertext and given
   * associated data.
   *
   * The associated data is not included in the ciphertext; instead, it's expected to match between
   * the encrypter and decrypter.
   *
   * @returns The decrypted data
   */
  decrypt(
    message: Uint8Array<ArrayBuffer>,
    nonce: Uint8Array<ArrayBuffer>,
    associatedData: Uint8Array<ArrayBuffer>
  ): Uint8Array<ArrayBuffer> {
    return Native.Aes256GcmSiv_Decrypt(this, message, nonce, associatedData);
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

  static deserialize(buf: Uint8Array<ArrayBuffer>): KEMSecretKey {
    return new KEMSecretKey(Native.KyberSecretKey_Deserialize(buf));
  }

  serialize(): Uint8Array<ArrayBuffer> {
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

/** The public information contained in a {@link KyberPreKeyRecord} */
export type SignedKyberPublicPreKey = {
  id: () => number;
  publicKey: () => KEMPublicKey;
  signature: () => Uint8Array<ArrayBuffer>;
};

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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): PreKeyRecord {
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

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.PreKeyRecord_Serialize(this);
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
    signature: Uint8Array<ArrayBuffer>
  ): KyberPreKeyRecord {
    return new KyberPreKeyRecord(
      Native.KyberPreKeyRecord_New(id, timestamp, keyPair, signature)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.KyberPreKeyRecord_Serialize(this);
  }

  static deserialize(buffer: Uint8Array<ArrayBuffer>): KyberPreKeyRecord {
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

  signature(): Uint8Array<ArrayBuffer> {
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
    macKey: Uint8Array<ArrayBuffer>,
    senderRatchetKey: PublicKey,
    counter: number,
    previousCounter: number,
    ciphertext: Uint8Array<ArrayBuffer>,
    senderIdentityKey: PublicKey,
    receiverIdentityKey: PublicKey,
    pqRatchet: Uint8Array<ArrayBuffer>
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SignalMessage {
    return new SignalMessage(Native.SignalMessage_Deserialize(buffer));
  }

  body(): Uint8Array<ArrayBuffer> {
    return Native.SignalMessage_GetBody(this);
  }

  pqRatchet(): Uint8Array<ArrayBuffer> {
    return Native.SignalMessage_GetPqRatchet(this);
  }

  counter(): number {
    return Native.SignalMessage_GetCounter(this);
  }

  messageVersion(): number {
    return Native.SignalMessage_GetMessageVersion(this);
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.SignalMessage_GetSerialized(this);
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    recevierIdentityKey: PublicKey,
    macKey: Uint8Array<ArrayBuffer>
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): PreKeySignalMessage {
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

  serialize(): Uint8Array<ArrayBuffer> {
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SessionRecord {
    return new SessionRecord(Native.SessionRecord_Deserialize(buffer));
  }

  serialize(): Uint8Array<ArrayBuffer> {
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): ServerCertificate {
    return new ServerCertificate(Native.ServerCertificate_Deserialize(buffer));
  }

  certificateData(): Uint8Array<ArrayBuffer> {
    return Native.ServerCertificate_GetCertificate(this);
  }

  key(): PublicKey {
    return PublicKey._fromNativeHandle(Native.ServerCertificate_GetKey(this));
  }

  keyId(): number {
    return Native.ServerCertificate_GetKeyId(this);
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.ServerCertificate_GetSerialized(this);
  }

  signature(): Uint8Array<ArrayBuffer> {
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SenderKeyRecord {
    return new SenderKeyRecord(Native.SenderKeyRecord_Deserialize(buffer));
  }

  serialize(): Uint8Array<ArrayBuffer> {
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SenderCertificate {
    return new SenderCertificate(Native.SenderCertificate_Deserialize(buffer));
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.SenderCertificate_GetSerialized(this);
  }

  certificate(): Uint8Array<ArrayBuffer> {
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
  signature(): Uint8Array<ArrayBuffer> {
    return Native.SenderCertificate_GetSignature(this);
  }

  /**
   * Validates `this` against the given trust root at the given current time.
   *
   * @see validateWithTrustRoots
   */
  validate(trustRoot: PublicKey, time: number): boolean {
    return Native.SenderCertificate_Validate(this, [trustRoot], time);
  }

  /**
   * Validates `this` against the given trust roots at the given current time.
   *
   * Checks the certificate against each key in `trustRoots` in constant time (that is, no result
   * is produced until every key is checked), making sure **one** of them has signed its embedded
   * server certificate. The `time` parameter is compared numerically against ``expiration``, and
   * is not required to use any specific units, but Signal uses milliseconds since 1970.
   */
  validateWithTrustRoots(trustRoots: PublicKey[], time: number): boolean {
    return Native.SenderCertificate_Validate(this, trustRoots, time);
  }
}

function bridgeSenderKeyStore(
  store: SenderKeyStore
): Native.BridgeSenderKeyStore {
  return {
    async storeSenderKey(
      sender: Native.ProtocolAddress,
      distributionId: Native.Uuid,
      record: Native.SenderKeyRecord
    ): Promise<void> {
      return store.saveSenderKey(
        ProtocolAddress._fromNativeHandle(sender),
        uuid.stringify(distributionId),
        SenderKeyRecord._fromNativeHandle(record)
      );
    },
    async loadSenderKey(
      sender: Native.ProtocolAddress,
      distributionId: Native.Uuid
    ): Promise<Native.SenderKeyRecord | null> {
      const sk = await store.getSenderKey(
        ProtocolAddress._fromNativeHandle(sender),
        uuid.stringify(distributionId)
      );
      return sk ? sk._nativeHandle : null;
    },
  };
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
      bridgeSenderKeyStore(store)
    );
    return new SenderKeyDistributionMessage(handle);
  }

  static _new(
    messageVersion: number,
    distributionId: Uuid,
    chainId: number,
    iteration: number,
    chainKey: Uint8Array<ArrayBuffer>,
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

  static deserialize(
    buffer: Uint8Array<ArrayBuffer>
  ): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      Native.SenderKeyDistributionMessage_Deserialize(buffer)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.SenderKeyDistributionMessage_Serialize(this);
  }

  chainKey(): Uint8Array<ArrayBuffer> {
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
  await Native.SenderKeyDistributionMessage_Process(
    sender,
    message,
    bridgeSenderKeyStore(store)
  );
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
    ciphertext: Uint8Array<ArrayBuffer>,
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): SenderKeyMessage {
    return new SenderKeyMessage(Native.SenderKeyMessage_Deserialize(buffer));
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.SenderKeyMessage_Serialize(this);
  }

  ciphertext(): Uint8Array<ArrayBuffer> {
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
    groupId: Uint8Array<ArrayBuffer> | null
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

  static deserialize(
    buffer: Uint8Array<ArrayBuffer>
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      Native.UnidentifiedSenderMessageContent_Deserialize(buffer)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.UnidentifiedSenderMessageContent_Serialize(this);
  }

  contents(): Uint8Array<ArrayBuffer> {
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

  groupId(): Uint8Array<ArrayBuffer> | null {
    return Native.UnidentifiedSenderMessageContent_GetGroupId(this);
  }
}

export abstract class SessionStore {
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

export abstract class IdentityKeyStore {
  abstract getIdentityKey(): Promise<PrivateKey>;
  async getIdentityKeyPair(): Promise<IdentityKeyPair> {
    const privKey = await this.getIdentityKey();
    return new IdentityKeyPair(privKey.getPublicKey(), privKey);
  }
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

export abstract class PreKeyStore {
  abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>;
  abstract getPreKey(id: number): Promise<PreKeyRecord>;
  abstract removePreKey(id: number): Promise<void>;
}

export abstract class SignedPreKeyStore {
  abstract saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord
  ): Promise<void>;
  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}

export abstract class KyberPreKeyStore {
  abstract saveKyberPreKey(
    kyberPreKeyId: number,
    record: KyberPreKeyRecord
  ): Promise<void>;
  abstract getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;
  abstract markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKey: PublicKey
  ): Promise<void>;
}

export abstract class SenderKeyStore {
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
  message: Uint8Array<ArrayBuffer>
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await Native.GroupCipher_EncryptMessage(
      sender,
      uuid.parse(distributionId),
      message,
      bridgeSenderKeyStore(store)
    )
  );
}

export async function groupDecrypt(
  sender: ProtocolAddress,
  store: SenderKeyStore,
  message: Uint8Array<ArrayBuffer>
): Promise<Uint8Array<ArrayBuffer>> {
  return Native.GroupCipher_DecryptMessage(
    sender,
    message,
    bridgeSenderKeyStore(store)
  );
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

  message(): Uint8Array<ArrayBuffer> {
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
  asCiphertextMessage: () => CiphertextMessage;
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

  serialize(): Uint8Array<ArrayBuffer> {
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): PlaintextContent {
    return new PlaintextContent(Native.PlaintextContent_Deserialize(buffer));
  }

  static from(message: DecryptionErrorMessage): PlaintextContent {
    return new PlaintextContent(
      Native.PlaintextContent_FromDecryptionErrorMessage(message)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.PlaintextContent_Serialize(this);
  }

  body(): Uint8Array<ArrayBuffer> {
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
    bytes: Uint8Array<ArrayBuffer>,
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

  static deserialize(buffer: Uint8Array<ArrayBuffer>): DecryptionErrorMessage {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_Deserialize(buffer)
    );
  }

  static extractFromSerializedBody(
    buffer: Uint8Array<ArrayBuffer>
  ): DecryptionErrorMessage {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ExtractFromSerializedContent(buffer)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
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

function bridgeSessionStore(store: SessionStore): Native.BridgeSessionStore {
  return {
    async storeSession(
      rawAddress: Native.ProtocolAddress,
      record: Native.SessionRecord
    ): Promise<void> {
      return store.saveSession(
        ProtocolAddress._fromNativeHandle(rawAddress),
        SessionRecord._fromNativeHandle(record)
      );
    },
    async loadSession(
      rawAddress: Native.ProtocolAddress
    ): Promise<Native.SessionRecord | null> {
      const pk = await store.getSession(
        ProtocolAddress._fromNativeHandle(rawAddress)
      );
      return pk ? pk._nativeHandle : null;
    },
  };
}

function bridgeIdentityKeyStore(
  store: IdentityKeyStore
): Native.BridgeIdentityKeyStore {
  return {
    async getLocalIdentityKeyPair(): Promise<
      [Native.PrivateKey, Native.PublicKey]
    > {
      const keyPair = await store.getIdentityKeyPair();
      return [
        keyPair.privateKey._nativeHandle,
        keyPair.publicKey._nativeHandle,
      ];
    },
    async getLocalRegistrationId(): Promise<number> {
      return store.getLocalRegistrationId();
    },
    async saveIdentityKey(
      name: Native.ProtocolAddress,
      key: Native.PublicKey
    ): Promise<Native.IdentityChange> {
      return store.saveIdentity(
        ProtocolAddress._fromNativeHandle(name),
        PublicKey._fromNativeHandle(key)
      );
    },
    async isTrustedIdentity(
      name: Native.ProtocolAddress,
      key: Native.PublicKey,
      direction: number
    ): Promise<boolean> {
      return store.isTrustedIdentity(
        ProtocolAddress._fromNativeHandle(name),
        PublicKey._fromNativeHandle(key),
        direction as Direction
      );
    },
    async getIdentityKey(
      name: Native.ProtocolAddress
    ): Promise<Native.PublicKey | null> {
      const key = await store.getIdentity(
        ProtocolAddress._fromNativeHandle(name)
      );
      return key ? key._nativeHandle : null;
    },
  };
}

export function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  now: Date = new Date()
): Promise<void> {
  return Native.SessionBuilder_ProcessPreKeyBundle(
    bundle,
    address,
    bridgeSessionStore(sessionStore),
    bridgeIdentityKeyStore(identityStore),
    now.getTime()
  );
}

export async function signalEncrypt(
  message: Uint8Array<ArrayBuffer>,
  address: ProtocolAddress,
  localAddress: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  now: Date = new Date()
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await Native.SessionCipher_EncryptMessage(
      message,
      address,
      localAddress,
      bridgeSessionStore(sessionStore),
      bridgeIdentityKeyStore(identityStore),
      now.getTime()
    )
  );
}

export function signalDecrypt(
  message: SignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Uint8Array<ArrayBuffer>> {
  return Native.SessionCipher_DecryptSignalMessage(
    message,
    address,
    bridgeSessionStore(sessionStore),
    bridgeIdentityKeyStore(identityStore)
  );
}

function bridgePreKeyStore(store: PreKeyStore): Native.BridgePreKeyStore {
  return {
    async storePreKey(id: number, record: Native.PreKeyRecord): Promise<void> {
      return store.savePreKey(id, PreKeyRecord._fromNativeHandle(record));
    },
    async loadPreKey(id: number): Promise<Native.PreKeyRecord> {
      const pk = await store.getPreKey(id);
      return pk._nativeHandle;
    },
    async removePreKey(id: number): Promise<void> {
      return store.removePreKey(id);
    },
  };
}

function bridgeSignedPreKeyStore(
  store: SignedPreKeyStore
): Native.BridgeSignedPreKeyStore {
  return {
    async storeSignedPreKey(
      id: number,
      record: Native.SignedPreKeyRecord
    ): Promise<void> {
      return store.saveSignedPreKey(
        id,
        SignedPreKeyRecord._fromNativeHandle(record)
      );
    },
    async loadSignedPreKey(id: number): Promise<Native.SignedPreKeyRecord> {
      const pk = await store.getSignedPreKey(id);
      return pk._nativeHandle;
    },
  };
}

function bridgeKyberPreKeyStore(
  store: KyberPreKeyStore
): Native.BridgeKyberPreKeyStore {
  return {
    async storeKyberPreKey(
      id: number,
      record: Native.KyberPreKeyRecord
    ): Promise<void> {
      return store.saveKyberPreKey(
        id,
        KyberPreKeyRecord._fromNativeHandle(record)
      );
    },
    async loadKyberPreKey(id: number): Promise<Native.KyberPreKeyRecord> {
      const pk = await store.getKyberPreKey(id);
      return pk._nativeHandle;
    },
    async markKyberPreKeyUsed(
      id: number,
      ecPrekeyId: number,
      baseKey: Native.PublicKey
    ): Promise<void> {
      return store.markKyberPreKeyUsed(
        id,
        ecPrekeyId,
        PublicKey._fromNativeHandle(baseKey)
      );
    },
  };
}

export function signalDecryptPreKey(
  message: PreKeySignalMessage,
  address: ProtocolAddress,
  localAddress: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore,
  kyberPrekeyStore: KyberPreKeyStore
): Promise<Uint8Array<ArrayBuffer>> {
  return Native.SessionCipher_DecryptPreKeySignalMessage(
    message,
    address,
    localAddress,
    bridgeSessionStore(sessionStore),
    bridgeIdentityKeyStore(identityStore),
    bridgePreKeyStore(prekeyStore),
    bridgeSignedPreKeyStore(signedPrekeyStore),
    bridgeKyberPreKeyStore(kyberPrekeyStore)
  );
}

export async function sealedSenderEncryptMessage(
  message: Uint8Array<ArrayBuffer>,
  address: ProtocolAddress,
  senderCert: SenderCertificate,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Uint8Array<ArrayBuffer>> {
  const localAddress = ProtocolAddress.new(
    senderCert.senderUuid(),
    senderCert.senderDeviceId()
  );
  const ciphertext = await signalEncrypt(
    message,
    address,
    localAddress,
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
): Promise<Uint8Array<ArrayBuffer>> {
  return Native.SealedSender_Encrypt(
    address,
    content,
    bridgeIdentityKeyStore(identityStore)
  );
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
): Promise<Uint8Array<ArrayBuffer>>;
export async function sealedSenderMultiRecipientEncrypt(
  content: UnidentifiedSenderMessageContent,
  recipients: ProtocolAddress[],
  identityStore: IdentityKeyStore,
  sessionStore: SessionStore
): Promise<Uint8Array<ArrayBuffer>>;

export async function sealedSenderMultiRecipientEncrypt(
  contentOrOptions:
    | UnidentifiedSenderMessageContent
    | SealedSenderMultiRecipientEncryptOptions,
  recipients?: ProtocolAddress[],
  identityStore?: IdentityKeyStore,
  sessionStore?: SessionStore
): Promise<Uint8Array<ArrayBuffer>> {
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
    bridgeIdentityKeyStore(identityStore)
  );
}

// For testing only
export function sealedSenderMultiRecipientMessageForSingleRecipient(
  message: Uint8Array<ArrayBuffer>
): Uint8Array<ArrayBuffer> {
  return Native.SealedSender_MultiRecipientMessageForSingleRecipient(message);
}

export async function sealedSenderDecryptMessage(
  message: Uint8Array<ArrayBuffer>,
  trustRoot: PublicKey,
  timestamp: number,
  localE164: string | null,
  localUuid: string,
  localDeviceId: number,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore,
  kyberPrekeyStore: KyberPreKeyStore
): Promise<SealedSenderDecryptionResult> {
  const ssdr = await Native.SealedSender_DecryptMessage(
    message,
    trustRoot,
    timestamp,
    localE164,
    localUuid,
    localDeviceId,
    bridgeSessionStore(sessionStore),
    bridgeIdentityKeyStore(identityStore),
    bridgePreKeyStore(prekeyStore),
    bridgeSignedPreKeyStore(signedPrekeyStore),
    bridgeKyberPreKeyStore(kyberPrekeyStore)
  );
  return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
}

export async function sealedSenderDecryptToUsmc(
  message: Uint8Array<ArrayBuffer>,
  identityStore: IdentityKeyStore
): Promise<UnidentifiedSenderMessageContent> {
  const usmc = await Native.SealedSender_DecryptToUsmc(
    message,
    bridgeIdentityKeyStore(identityStore)
  );
  return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
}

export class Cds2Client {
  readonly _nativeHandle: Native.SgxClientState;

  private constructor(nativeHandle: Native.SgxClientState) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    mrenclave: Uint8Array<ArrayBuffer>,
    attestationMsg: Uint8Array<ArrayBuffer>,
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

  initialRequest(): Uint8Array<ArrayBuffer> {
    return Native.SgxClientState_InitialRequest(this);
  }

  completeHandshake(buffer: Uint8Array<ArrayBuffer>): void {
    return Native.SgxClientState_CompleteHandshake(this, buffer);
  }

  establishedSend(buffer: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
    return Native.SgxClientState_EstablishedSend(this, buffer);
  }

  establishedRecv(buffer: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
    return Native.SgxClientState_EstablishedRecv(this, buffer);
  }
}

export class HsmEnclaveClient {
  readonly _nativeHandle: Native.HsmEnclaveClient;

  private constructor(nativeHandle: Native.HsmEnclaveClient) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    public_key: Uint8Array<ArrayBuffer>,
    code_hashes: Uint8Array<ArrayBuffer>[]
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

  initialRequest(): Uint8Array<ArrayBuffer> {
    return Native.HsmEnclaveClient_InitialRequest(this);
  }

  completeHandshake(buffer: Uint8Array<ArrayBuffer>): void {
    return Native.HsmEnclaveClient_CompleteHandshake(this, buffer);
  }

  establishedSend(buffer: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
    return Native.HsmEnclaveClient_EstablishedSend(this, buffer);
  }

  establishedRecv(buffer: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
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
