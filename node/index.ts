//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as os from 'os';
import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

const SC = bindings(
  'libsignal_client_' + os.platform() + '_' + process.arch
) as typeof SignalClient;

export const { initLogger, LogLevel } = SC;

export const enum CiphertextMessageType {
  Whisper = 2,
  PreKey = 3,
  SenderKey = 4,
  SenderKeyDistribution = 5,
}

export const enum Direction {
  Sending,
  Receiving,
}

export class HKDF {
  private readonly version: number;

  private constructor(version: number) {
    this.version = version;
  }

  static new(version: number): HKDF {
    return new HKDF(version);
  }

  deriveSecrets(
    outputLength: number,
    keyMaterial: Buffer,
    label: Buffer,
    salt: Buffer | null
  ): Buffer {
    return SC.HKDF_DeriveSecrets(
      outputLength,
      this.version,
      keyMaterial,
      label,
      salt
    );
  }
}

export class ScannableFingerprint {
  private readonly scannable: Buffer;

  private constructor(scannable: Buffer) {
    this.scannable = scannable;
  }

  static _fromBuffer(scannable: Buffer): ScannableFingerprint {
    return new ScannableFingerprint(scannable);
  }

  compare(other: ScannableFingerprint): boolean {
    return SC.ScannableFingerprint_Compare(this.scannable, other.scannable);
  }

  toBuffer(): Buffer {
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
  readonly _nativeHandle: SignalClient.Fingerprint;

  private constructor(nativeHandle: SignalClient.Fingerprint) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    iterations: number,
    version: number,
    localIdentifier: Buffer,
    localKey: PublicKey,
    remoteIdentifier: Buffer,
    remoteKey: PublicKey
  ): Fingerprint {
    return new Fingerprint(
      SC.Fingerprint_New(
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
      SC.Fingerprint_DisplayString(this)
    );
  }

  public scannableFingerprint(): ScannableFingerprint {
    return ScannableFingerprint._fromBuffer(
      SC.Fingerprint_ScannableEncoding(this)
    );
  }
}

export class Aes256GcmSiv {
  readonly _nativeHandle: SignalClient.Aes256GcmSiv;

  private constructor(key: Buffer) {
    this._nativeHandle = SC.Aes256GcmSiv_New(key);
  }

  static new(key: Buffer): Aes256GcmSiv {
    return new Aes256GcmSiv(key);
  }

  encrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return SC.Aes256GcmSiv_Encrypt(this, message, nonce, associated_data);
  }

  decrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return SC.Aes256GcmSiv_Decrypt(this, message, nonce, associated_data);
  }
}

export class ProtocolAddress {
  readonly _nativeHandle: SignalClient.ProtocolAddress;

  private constructor(handle: SignalClient.ProtocolAddress) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    handle: SignalClient.ProtocolAddress
  ): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(SC.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return SC.ProtocolAddress_Name(this);
  }

  deviceId(): number {
    return SC.ProtocolAddress_DeviceId(this);
  }
}

export class PublicKey {
  readonly _nativeHandle: SignalClient.PublicKey;

  private constructor(handle: SignalClient.PublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: SignalClient.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(SC.PublicKey_Deserialize(buf));
  }

  /// Returns -1, 0, or 1
  compare(other: PublicKey): number {
    return SC.PublicKey_Compare(this, other);
  }

  serialize(): Buffer {
    return SC.PublicKey_Serialize(this);
  }

  getPublicKeyBytes(): Buffer {
    return SC.PublicKey_GetPublicKeyBytes(this);
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return SC.PublicKey_Verify(this, msg, sig);
  }
}

export class PrivateKey {
  readonly _nativeHandle: SignalClient.PrivateKey;

  private constructor(handle: SignalClient.PrivateKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: SignalClient.PrivateKey): PrivateKey {
    return new PrivateKey(handle);
  }

  static generate(): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Generate());
  }

  static deserialize(buf: Buffer): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PrivateKey_Serialize(this);
  }

  sign(msg: Buffer): Buffer {
    return SC.PrivateKey_Sign(this, msg);
  }

  agree(other_key: PublicKey): Buffer {
    return SC.PrivateKey_Agree(this, other_key);
  }

  getPublicKey(): PublicKey {
    return PublicKey._fromNativeHandle(SC.PrivateKey_GetPublicKey(this));
  }
}

export class IdentityKeyPair {
  private readonly publicKey: PublicKey;
  private readonly privateKey: PrivateKey;

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static new(publicKey: PublicKey, privateKey: PrivateKey): IdentityKeyPair {
    return new IdentityKeyPair(publicKey, privateKey);
  }

  serialize(): Buffer {
    return SC.IdentityKeyPair_Serialize(this.publicKey, this.privateKey);
  }
}

export class PreKeyBundle {
  readonly _nativeHandle: SignalClient.PreKeyBundle;

  private constructor(handle: SignalClient.PreKeyBundle) {
    this._nativeHandle = handle;
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
        prekey != null ? prekey : null,
        //prekey?,
        signed_prekey_id,
        signed_prekey,
        signed_prekey_signature,
        identity_key
      )
    );
  }

  deviceId(): number {
    return SC.PreKeyBundle_GetDeviceId(this);
  }
  identityKey(): PublicKey {
    return PublicKey._fromNativeHandle(SC.PreKeyBundle_GetIdentityKey(this));
  }
  preKeyId(): number | null {
    return SC.PreKeyBundle_GetPreKeyId(this);
  }
  preKeyPublic(): PublicKey | null {
    const handle = SC.PreKeyBundle_GetPreKeyPublic(this);

    if (handle == null) {
      return null;
    } else {
      return PublicKey._fromNativeHandle(handle);
    }
  }
  registrationId(): number {
    return SC.PreKeyBundle_GetRegistrationId(this);
  }
  signedPreKeyId(): number {
    return SC.PreKeyBundle_GetSignedPreKeyId(this);
  }
  signedPreKeyPublic(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.PreKeyBundle_GetSignedPreKeyPublic(this)
    );
  }
  signedPreKeySignature(): Buffer {
    return SC.PreKeyBundle_GetSignedPreKeySignature(this);
  }
}

export class PreKeyRecord {
  readonly _nativeHandle: SignalClient.PreKeyRecord;

  private constructor(handle: SignalClient.PreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.PreKeyRecord
  ): PreKeyRecord {
    return new PreKeyRecord(nativeHandle);
  }

  static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
    return new PreKeyRecord(SC.PreKeyRecord_New(id, pubKey, privKey));
  }

  static deserialize(buffer: Buffer): PreKeyRecord {
    return new PreKeyRecord(SC.PreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return SC.PreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(SC.PreKeyRecord_GetPrivateKey(this));
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(SC.PreKeyRecord_GetPublicKey(this));
  }

  serialize(): Buffer {
    return SC.PreKeyRecord_Serialize(this);
  }
}

export class SignedPreKeyRecord {
  readonly _nativeHandle: SignalClient.SignedPreKeyRecord;

  private constructor(handle: SignalClient.SignedPreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SignedPreKeyRecord
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(nativeHandle);
  }

  static new(
    id: number,
    timestamp: number,
    pubKey: PublicKey,
    privKey: PrivateKey,
    signature: Buffer
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      SC.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature)
    );
  }

  static deserialize(buffer: Buffer): SignedPreKeyRecord {
    return new SignedPreKeyRecord(SC.SignedPreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return SC.SignedPreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      SC.SignedPreKeyRecord_GetPrivateKey(this)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.SignedPreKeyRecord_GetPublicKey(this)
    );
  }

  serialize(): Buffer {
    return SC.SignedPreKeyRecord_Serialize(this);
  }

  signature(): Buffer {
    return SC.SignedPreKeyRecord_GetSignature(this);
  }

  timestamp(): number {
    return SC.SignedPreKeyRecord_GetTimestamp(this);
  }
}

export class SignalMessage {
  readonly _nativeHandle: SignalClient.SignalMessage;

  private constructor(handle: SignalClient.SignalMessage) {
    this._nativeHandle = handle;
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
        senderRatchetKey,
        counter,
        previousCounter,
        ciphertext,
        senderIdentityKey,
        receiverIdentityKey
      )
    );
  }

  static deserialize(buffer: Buffer): SignalMessage {
    return new SignalMessage(SC.SignalMessage_Deserialize(buffer));
  }

  body(): Buffer {
    return SC.SignalMessage_GetBody(this);
  }

  counter(): number {
    return SC.SignalMessage_GetCounter(this);
  }

  messageVersion(): number {
    return SC.SignalMessage_GetMessageVersion(this);
  }

  serialize(): Buffer {
    return SC.SignalMessage_GetSerialized(this);
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    recevierIdentityKey: PublicKey,
    macKey: Buffer
  ): boolean {
    return SC.SignalMessage_VerifyMac(
      this,
      senderIdentityKey,
      recevierIdentityKey,
      macKey
    );
  }
}

export class PreKeySignalMessage {
  readonly _nativeHandle: SignalClient.PreKeySignalMessage;

  private constructor(handle: SignalClient.PreKeySignalMessage) {
    this._nativeHandle = handle;
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
        baseKey,
        identityKey,
        signalMessage
      )
    );
  }

  static deserialize(buffer: Buffer): PreKeySignalMessage {
    return new PreKeySignalMessage(SC.PreKeySignalMessage_Deserialize(buffer));
  }

  preKeyId(): number | null {
    return SC.PreKeySignalMessage_GetPreKeyId(this);
  }

  registrationId(): number {
    return SC.PreKeySignalMessage_GetRegistrationId(this);
  }

  signedPreKeyId(): number {
    return SC.PreKeySignalMessage_GetSignedPreKeyId(this);
  }

  version(): number {
    return SC.PreKeySignalMessage_GetVersion(this);
  }

  serialize(): Buffer {
    return SC.PreKeySignalMessage_Serialize(this);
  }
}

export class SessionRecord {
  readonly _nativeHandle: SignalClient.SessionRecord;

  private constructor(nativeHandle: SignalClient.SessionRecord) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SessionRecord
  ): SessionRecord {
    return new SessionRecord(nativeHandle);
  }

  static deserialize(buffer: Buffer): SessionRecord {
    return new SessionRecord(SC.SessionRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SessionRecord_Serialize(this);
  }

  archiveCurrentState(): void {
    SC.SessionRecord_ArchiveCurrentState(this);
  }

  localRegistrationId(): number {
    return SC.SessionRecord_GetLocalRegistrationId(this);
  }

  remoteRegistrationId(): number {
    return SC.SessionRecord_GetRemoteRegistrationId(this);
  }
}

export class SenderKeyName {
  readonly _nativeHandle: SignalClient.SenderKeyName;

  private constructor(nativeHandle: SignalClient.SenderKeyName) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SenderKeyName
  ): SenderKeyName {
    return new SenderKeyName(nativeHandle);
  }

  static new(
    groupId: string,
    senderName: string,
    senderDeviceId: number
  ): SenderKeyName {
    return new SenderKeyName(
      SC.SenderKeyName_New(groupId, senderName, senderDeviceId)
    );
  }

  groupId(): string {
    return SC.SenderKeyName_GetGroupId(this);
  }

  senderName(): string {
    return SC.SenderKeyName_GetSenderName(this);
  }

  senderDeviceId(): number {
    return SC.SenderKeyName_GetSenderDeviceId(this);
  }
}

export class ServerCertificate {
  readonly _nativeHandle: SignalClient.ServerCertificate;

  static _fromNativeHandle(
    nativeHandle: SignalClient.ServerCertificate
  ): ServerCertificate {
    return new ServerCertificate(nativeHandle);
  }

  private constructor(nativeHandle: SignalClient.ServerCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    serverKey: PublicKey,
    trustRoot: PrivateKey
  ): ServerCertificate {
    return new ServerCertificate(
      SC.ServerCertificate_New(keyId, serverKey, trustRoot)
    );
  }

  static deserialize(buffer: Buffer): ServerCertificate {
    return new ServerCertificate(SC.ServerCertificate_Deserialize(buffer));
  }

  certificateData(): Buffer {
    return SC.ServerCertificate_GetCertificate(this);
  }

  key(): PublicKey {
    return PublicKey._fromNativeHandle(SC.ServerCertificate_GetKey(this));
  }

  keyId(): number {
    return SC.ServerCertificate_GetKeyId(this);
  }

  serialize(): Buffer {
    return SC.ServerCertificate_GetSerialized(this);
  }

  signature(): Buffer {
    return SC.ServerCertificate_GetSignature(this);
  }
}

export class SenderKeyRecord {
  readonly _nativeHandle: SignalClient.SenderKeyRecord;

  static _fromNativeHandle(
    nativeHandle: SignalClient.SenderKeyRecord
  ): SenderKeyRecord {
    return new SenderKeyRecord(nativeHandle);
  }

  private constructor(nativeHandle: SignalClient.SenderKeyRecord) {
    this._nativeHandle = nativeHandle;
  }

  static new(): SenderKeyRecord {
    return new SenderKeyRecord(SC.SenderKeyRecord_New());
  }

  static deserialize(buffer: Buffer): SenderKeyRecord {
    return new SenderKeyRecord(SC.SenderKeyRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderKeyRecord_Serialize(this);
  }
}

export class SenderCertificate {
  readonly _nativeHandle: SignalClient.SenderCertificate;

  private constructor(nativeHandle: SignalClient.SenderCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SenderCertificate
  ): SenderCertificate {
    return new SenderCertificate(nativeHandle);
  }

  static new(
    senderUuid: string,
    senderE164: string | null,
    senderDeviceId: number,
    senderKey: PublicKey,
    expiration: number,
    signerCert: ServerCertificate,
    signerKey: PrivateKey
  ): SenderCertificate {
    return new SenderCertificate(
      SC.SenderCertificate_New(
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

  static deserialize(buffer: Buffer): SenderCertificate {
    return new SenderCertificate(SC.SenderCertificate_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderCertificate_GetSerialized(this);
  }

  certificate(): Buffer {
    return SC.SenderCertificate_GetCertificate(this);
  }
  expiration(): number {
    return SC.SenderCertificate_GetExpiration(this);
  }
  key(): PublicKey {
    return PublicKey._fromNativeHandle(SC.SenderCertificate_GetKey(this));
  }
  senderE164(): string | null {
    return SC.SenderCertificate_GetSenderE164(this);
  }
  senderUuid(): string {
    return SC.SenderCertificate_GetSenderUuid(this);
  }
  senderDeviceId(): number {
    return SC.SenderCertificate_GetDeviceId(this);
  }
  serverCertificate(): ServerCertificate {
    return ServerCertificate._fromNativeHandle(
      SC.SenderCertificate_GetServerCertificate(this)
    );
  }
  signature(): Buffer {
    return SC.SenderCertificate_GetSignature(this);
  }
  validate(trustRoot: PublicKey, time: number): boolean {
    return SC.SenderCertificate_Validate(this, trustRoot, time);
  }
}

export class SenderKeyDistributionMessage {
  readonly _nativeHandle: SignalClient.SenderKeyDistributionMessage;

  private constructor(nativeHandle: SignalClient.SenderKeyDistributionMessage) {
    this._nativeHandle = nativeHandle;
  }

  static async create(
    name: SenderKeyName,
    store: SenderKeyStore
  ): Promise<SenderKeyDistributionMessage> {
    const handle = await SC.SenderKeyDistributionMessage_Create(name, store);
    return new SenderKeyDistributionMessage(handle);
  }

  static new(
    keyId: number,
    iteration: number,
    chainKey: Buffer,
    pk: PublicKey
  ): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      SC.SenderKeyDistributionMessage_New(keyId, iteration, chainKey, pk)
    );
  }

  static deserialize(buffer: Buffer): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      SC.SenderKeyDistributionMessage_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return SC.SenderKeyDistributionMessage_Serialize(this);
  }

  chainKey(): Buffer {
    return SC.SenderKeyDistributionMessage_GetChainKey(this);
  }

  iteration(): number {
    return SC.SenderKeyDistributionMessage_GetIteration(this);
  }

  id(): number {
    return SC.SenderKeyDistributionMessage_GetId(this);
  }
}

export async function processSenderKeyDistributionMessage(
  name: SenderKeyName,
  message: SenderKeyDistributionMessage,
  store: SenderKeyStore
): Promise<void> {
  await SC.SenderKeyDistributionMessage_Process(name, message, store);
}

export class SenderKeyMessage {
  readonly _nativeHandle: SignalClient.SenderKeyMessage;

  private constructor(nativeHandle: SignalClient.SenderKeyMessage) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    iteration: number,
    ciphertext: Buffer,
    pk: PrivateKey
  ): SenderKeyMessage {
    return new SenderKeyMessage(
      SC.SenderKeyMessage_New(keyId, iteration, ciphertext, pk)
    );
  }

  static deserialize(buffer: Buffer): SenderKeyMessage {
    return new SenderKeyMessage(SC.SenderKeyMessage_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderKeyMessage_Serialize(this);
  }

  ciphertext(): Buffer {
    return SC.SenderKeyMessage_GetCipherText(this);
  }

  iteration(): number {
    return SC.SenderKeyMessage_GetIteration(this);
  }

  keyId(): number {
    return SC.SenderKeyMessage_GetKeyId(this);
  }

  verifySignature(key: PublicKey): boolean {
    return SC.SenderKeyMessage_VerifySignature(this, key);
  }
}

export class UnidentifiedSenderMessageContent {
  readonly _nativeHandle: SignalClient.UnidentifiedSenderMessageContent;

  private constructor(
    nativeHandle: SignalClient.UnidentifiedSenderMessageContent
  ) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.UnidentifiedSenderMessageContent
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(nativeHandle);
  }

  static deserialize(buffer: Buffer): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      SC.UnidentifiedSenderMessageContent_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return SC.UnidentifiedSenderMessageContent_Serialize(this);
  }

  contents(): Buffer {
    return SC.UnidentifiedSenderMessageContent_GetContents(this);
  }

  msgType(): number {
    return SC.UnidentifiedSenderMessageContent_GetMsgType(this);
  }

  senderCertificate(): SenderCertificate {
    return SenderCertificate._fromNativeHandle(
      SC.UnidentifiedSenderMessageContent_GetSenderCert(this)
    );
  }
}

export abstract class SessionStore implements SignalClient.SessionStore {
  async _saveSession(
    name: SignalClient.ProtocolAddress,
    record: SignalClient.SessionRecord
  ): Promise<void> {
    return this.saveSession(
      ProtocolAddress._fromNativeHandle(name),
      SessionRecord._fromNativeHandle(record)
    );
  }
  async _getSession(
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.SessionRecord | null> {
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
}

export abstract class IdentityKeyStore
  implements SignalClient.IdentityKeyStore {
  async _getIdentityKey(): Promise<SignalClient.PrivateKey> {
    const key = await this.getIdentityKey();
    return key._nativeHandle;
  }

  async _getLocalRegistrationId(): Promise<number> {
    return this.getLocalRegistrationId();
  }
  async _saveIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey
  ): Promise<boolean> {
    return this.saveIdentity(
      ProtocolAddress._fromNativeHandle(name),
      PublicKey._fromNativeHandle(key)
    );
  }
  async _isTrustedIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey,
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
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.PublicKey | null> {
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
  ): Promise<boolean>;
  abstract isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    direction: Direction
  ): Promise<boolean>;
  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class PreKeyStore implements SignalClient.PreKeyStore {
  async _savePreKey(
    id: number,
    record: SignalClient.PreKeyRecord
  ): Promise<void> {
    return this.savePreKey(id, PreKeyRecord._fromNativeHandle(record));
  }
  async _getPreKey(id: number): Promise<SignalClient.PreKeyRecord> {
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

export abstract class SignedPreKeyStore
  implements SignalClient.SignedPreKeyStore {
  async _saveSignedPreKey(
    id: number,
    record: SignalClient.SignedPreKeyRecord
  ): Promise<void> {
    return this.saveSignedPreKey(
      id,
      SignedPreKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSignedPreKey(id: number): Promise<SignalClient.SignedPreKeyRecord> {
    const pk = await this.getSignedPreKey(id);
    return pk._nativeHandle;
  }

  abstract saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord
  ): Promise<void>;
  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}

export abstract class SenderKeyStore implements SignalClient.SenderKeyStore {
  async _saveSenderKey(
    name: SignalClient.SenderKeyName,
    record: SignalClient.SenderKeyRecord
  ): Promise<void> {
    return this.saveSenderKey(
      SenderKeyName._fromNativeHandle(name),
      SenderKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSenderKey(
    name: SignalClient.SenderKeyName
  ): Promise<SignalClient.SenderKeyRecord | null> {
    const skr = await this.getSenderKey(SenderKeyName._fromNativeHandle(name));
    if (skr == null) {
      return null;
    } else {
      return skr._nativeHandle;
    }
  }

  abstract saveSenderKey(
    name: SenderKeyName,
    record: SenderKeyRecord
  ): Promise<void>;
  abstract getSenderKey(name: SenderKeyName): Promise<SenderKeyRecord | null>;
}

export async function groupEncrypt(
  name: SenderKeyName,
  store: SenderKeyStore,
  message: Buffer
): Promise<Buffer> {
  return SC.GroupCipher_Encrypt(name, message, store);
}

export async function groupDecrypt(
  name: SenderKeyName,
  store: SenderKeyStore,
  message: Buffer
): Promise<Buffer> {
  return SC.GroupCipher_Decrypt(name, message, store);
}

export class SealedSenderDecryptionResult {
  readonly _nativeHandle: SignalClient.SealedSenderDecryptionResult;

  private constructor(nativeHandle: SignalClient.SealedSenderDecryptionResult) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SealedSenderDecryptionResult
  ): SealedSenderDecryptionResult {
    return new SealedSenderDecryptionResult(nativeHandle);
  }

  message(): Buffer {
    return SC.SealedSenderDecryptionResult_Message(this);
  }

  senderE164(): string | null {
    return SC.SealedSenderDecryptionResult_GetSenderE164(this);
  }

  senderUuid(): string {
    return SC.SealedSenderDecryptionResult_GetSenderUuid(this);
  }

  deviceId(): number {
    return SC.SealedSenderDecryptionResult_GetDeviceId(this);
  }
}

export class CiphertextMessage {
  readonly _nativeHandle: SignalClient.CiphertextMessage;

  private constructor(nativeHandle: SignalClient.CiphertextMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.CiphertextMessage
  ): CiphertextMessage {
    return new CiphertextMessage(nativeHandle);
  }

  serialize(): Buffer {
    return SC.CiphertextMessage_Serialize(this);
  }

  type(): number {
    return SC.CiphertextMessage_Type(this);
  }
}

export function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<void> {
  return SC.SessionBuilder_ProcessPreKeyBundle(
    bundle,
    address,
    sessionStore,
    identityStore
  );
}

export async function signalEncrypt(
  message: Buffer,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await SC.SessionCipher_EncryptMessage(
      message,
      address,
      sessionStore,
      identityStore
    )
  );
}

export function signalDecrypt(
  message: SignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  return SC.SessionCipher_DecryptSignalMessage(
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
  signedPrekeyStore: SignedPreKeyStore
): Promise<Buffer> {
  return SC.SessionCipher_DecryptPreKeySignalMessage(
    message,
    address,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore
  );
}

export function sealedSenderEncryptMessage(
  message: Buffer,
  address: ProtocolAddress,
  senderCert: SenderCertificate,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  return SC.SealedSender_EncryptMessage(
    address,
    senderCert,
    message,
    sessionStore,
    identityStore
  );
}

export async function sealedSenderDecryptMessage(
  message: Buffer,
  trustRoot: PublicKey,
  timestamp: number,
  localE164: string | null,
  localUuid: string,
  localDeviceId: number,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore
): Promise<SealedSenderDecryptionResult> {
  const ssdr = await SC.SealedSender_DecryptMessage(
    message,
    trustRoot,
    timestamp,
    localE164,
    localUuid,
    localDeviceId,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore
  );
  return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
}

export async function sealedSenderDecryptToUsmc(
  message: Buffer,
  identityStore: IdentityKeyStore
): Promise<UnidentifiedSenderMessageContent> {
  const usmc = await SC.SealedSender_DecryptToUsmc(message, identityStore);
  return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
}
