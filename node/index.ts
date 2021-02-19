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
  private readonly nativeHandle: SignalClient.Fingerprint;

  private constructor(nativeHandle: SignalClient.Fingerprint) {
    this.nativeHandle = nativeHandle;
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
        localKey._unsafeGetNativeHandle(),
        remoteIdentifier,
        remoteKey._unsafeGetNativeHandle()
      )
    );
  }

  public displayableFingerprint(): DisplayableFingerprint {
    return DisplayableFingerprint._fromString(
      SC.Fingerprint_DisplayString(this.nativeHandle)
    );
  }

  public scannableFingerprint(): ScannableFingerprint {
    return ScannableFingerprint._fromBuffer(
      SC.Fingerprint_ScannableEncoding(this.nativeHandle)
    );
  }
}

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

  _unsafeGetNativeHandle(): SignalClient.ProtocolAddress {
    return this.nativeHandle;
  }

  private constructor(handle: SignalClient.ProtocolAddress) {
    this.nativeHandle = handle;
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

  static _fromNativeHandle(handle: SignalClient.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(SC.PublicKey_Deserialize(buf));
  }

  /// Returns -1, 0, or 1
  compare(other: PublicKey): number {
    return SC.PublicKey_Compare(this.nativeHandle, other.nativeHandle);
  }

  serialize(): Buffer {
    return SC.PublicKey_Serialize(this.nativeHandle);
  }

  getPublicKeyBytes(): Buffer {
    return SC.PublicKey_GetPublicKeyBytes(this.nativeHandle);
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

  static _fromNativeHandle(handle: SignalClient.PrivateKey): PrivateKey {
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
    return PublicKey._fromNativeHandle(
      SC.PrivateKey_GetPublicKey(this.nativeHandle)
    );
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
    return SC.IdentityKeyPair_Serialize(
      this.publicKey._unsafeGetNativeHandle(),
      this.privateKey._unsafeGetNativeHandle()
    );
  }
}

export class PreKeyBundle {
  private readonly nativeHandle: SignalClient.PreKeyBundle;

  _unsafeGetNativeHandle(): SignalClient.PreKeyBundle {
    return this.nativeHandle;
  }

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
    return PublicKey._fromNativeHandle(
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
      return PublicKey._fromNativeHandle(handle);
    }
  }
  registrationId(): number {
    return SC.PreKeyBundle_GetRegistrationId(this.nativeHandle);
  }
  signedPreKeyId(): number {
    return SC.PreKeyBundle_GetSignedPreKeyId(this.nativeHandle);
  }
  signedPreKeyPublic(): PublicKey {
    return PublicKey._fromNativeHandle(
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

  _unsafeGetNativeHandle(): SignalClient.PreKeyRecord {
    return this.nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.PreKeyRecord
  ): PreKeyRecord {
    return new PreKeyRecord(nativeHandle);
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
    return PrivateKey._fromNativeHandle(
      SC.PreKeyRecord_GetPrivateKey(this.nativeHandle)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.PreKeyRecord_GetPublicKey(this.nativeHandle)
    );
  }

  serialize(): Buffer {
    return SC.PreKeyRecord_Serialize(this.nativeHandle);
  }
}

export class SignedPreKeyRecord {
  private readonly nativeHandle: SignalClient.SignedPreKeyRecord;

  private constructor(handle: SignalClient.SignedPreKeyRecord) {
    this.nativeHandle = handle;
  }

  _unsafeGetNativeHandle(): SignalClient.SignedPreKeyRecord {
    return this.nativeHandle;
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
      SC.SignedPreKeyRecord_New(
        id,
        timestamp,
        pubKey._unsafeGetNativeHandle(),
        privKey._unsafeGetNativeHandle(),
        signature
      )
    );
  }

  static deserialize(buffer: Buffer): SignedPreKeyRecord {
    return new SignedPreKeyRecord(SC.SignedPreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return SC.SignedPreKeyRecord_GetId(this.nativeHandle);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      SC.SignedPreKeyRecord_GetPrivateKey(this.nativeHandle)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.SignedPreKeyRecord_GetPublicKey(this.nativeHandle)
    );
  }

  serialize(): Buffer {
    return SC.SignedPreKeyRecord_Serialize(this.nativeHandle);
  }

  signature(): Buffer {
    return SC.SignedPreKeyRecord_GetSignature(this.nativeHandle);
  }

  timestamp(): number {
    return SC.SignedPreKeyRecord_GetTimestamp(this.nativeHandle);
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

  _unsafeGetNativeHandle(): SignalClient.PreKeySignalMessage {
    return this.nativeHandle;
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

export class SessionRecord {
  private readonly nativeHandle: SignalClient.SessionRecord;

  private constructor(nativeHandle: SignalClient.SessionRecord) {
    this.nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SessionRecord
  ): SessionRecord {
    return new SessionRecord(nativeHandle);
  }

  _unsafeGetNativeHandle(): SignalClient.SessionRecord {
    return this.nativeHandle;
  }

  static deserialize(buffer: Buffer): SessionRecord {
    return new SessionRecord(SC.SessionRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SessionRecord_Serialize(this.nativeHandle);
  }

  archiveCurrentState(): void {
    SC.SessionRecord_ArchiveCurrentState(this.nativeHandle);
  }

  localRegistrationId(): number {
    return SC.SessionRecord_GetLocalRegistrationId(this.nativeHandle);
  }

  remoteRegistrationId(): number {
    return SC.SessionRecord_GetRemoteRegistrationId(this.nativeHandle);
  }
}

export class SenderKeyName {
  private readonly nativeHandle: SignalClient.SenderKeyName;

  private constructor(nativeHandle: SignalClient.SenderKeyName) {
    this.nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SenderKeyName
  ): SenderKeyName {
    return new SenderKeyName(nativeHandle);
  }

  _unsafeGetNativeHandle(): SignalClient.SenderKeyName {
    return this.nativeHandle;
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
    return SC.SenderKeyName_GetGroupId(this.nativeHandle);
  }

  senderName(): string {
    return SC.SenderKeyName_GetSenderName(this.nativeHandle);
  }

  senderDeviceId(): number {
    return SC.SenderKeyName_GetSenderDeviceId(this.nativeHandle);
  }
}

export class ServerCertificate {
  private readonly nativeHandle: SignalClient.ServerCertificate;

  _unsafeGetNativeHandle(): SignalClient.ServerCertificate {
    return this.nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.ServerCertificate
  ): ServerCertificate {
    return new ServerCertificate(nativeHandle);
  }

  private constructor(nativeHandle: SignalClient.ServerCertificate) {
    this.nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    serverKey: PublicKey,
    trustRoot: PrivateKey
  ): ServerCertificate {
    return new ServerCertificate(
      SC.ServerCertificate_New(
        keyId,
        serverKey._unsafeGetNativeHandle(),
        trustRoot._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): ServerCertificate {
    return new ServerCertificate(SC.ServerCertificate_Deserialize(buffer));
  }

  certificateData(): Buffer {
    return SC.ServerCertificate_GetCertificate(this.nativeHandle);
  }

  key(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.ServerCertificate_GetKey(this.nativeHandle)
    );
  }

  keyId(): number {
    return SC.ServerCertificate_GetKeyId(this.nativeHandle);
  }

  serialize(): Buffer {
    return SC.ServerCertificate_GetSerialized(this.nativeHandle);
  }

  signature(): Buffer {
    return SC.ServerCertificate_GetSignature(this.nativeHandle);
  }
}

export class SenderKeyRecord {
  private readonly nativeHandle: SignalClient.SenderKeyRecord;

  _unsafeGetNativeHandle(): SignalClient.SenderKeyRecord {
    return this.nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SenderKeyRecord
  ): SenderKeyRecord {
    return new SenderKeyRecord(nativeHandle);
  }

  private constructor(nativeHandle: SignalClient.SenderKeyRecord) {
    this.nativeHandle = nativeHandle;
  }

  static new(): SenderKeyRecord {
    return new SenderKeyRecord(SC.SenderKeyRecord_New());
  }

  static deserialize(buffer: Buffer): SenderKeyRecord {
    return new SenderKeyRecord(SC.SenderKeyRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderKeyRecord_Serialize(this.nativeHandle);
  }
}

export class SenderCertificate {
  private readonly nativeHandle: SignalClient.SenderCertificate;

  private constructor(nativeHandle: SignalClient.SenderCertificate) {
    this.nativeHandle = nativeHandle;
  }

  _unsafeGetNativeHandle(): SignalClient.SenderCertificate {
    return this.nativeHandle;
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
        senderKey._unsafeGetNativeHandle(),
        expiration,
        signerCert._unsafeGetNativeHandle(),
        signerKey._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): SenderCertificate {
    return new SenderCertificate(SC.SenderCertificate_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderCertificate_GetSerialized(this.nativeHandle);
  }

  certificate(): Buffer {
    return SC.SenderCertificate_GetCertificate(this.nativeHandle);
  }
  expiration(): number {
    return SC.SenderCertificate_GetExpiration(this.nativeHandle);
  }
  key(): PublicKey {
    return PublicKey._fromNativeHandle(
      SC.SenderCertificate_GetKey(this.nativeHandle)
    );
  }
  senderE164(): string | null {
    return SC.SenderCertificate_GetSenderE164(this.nativeHandle);
  }
  senderUuid(): string {
    return SC.SenderCertificate_GetSenderUuid(this.nativeHandle);
  }
  senderDeviceId(): number {
    return SC.SenderCertificate_GetDeviceId(this.nativeHandle);
  }
  serverCertificate(): ServerCertificate {
    return ServerCertificate._fromNativeHandle(
      SC.SenderCertificate_GetServerCertificate(this.nativeHandle)
    );
  }
  signature(): Buffer {
    return SC.SenderCertificate_GetSignature(this.nativeHandle);
  }
  validate(trustRoot: PublicKey, time: number): boolean {
    return SC.SenderCertificate_Validate(
      this.nativeHandle,
      trustRoot._unsafeGetNativeHandle(),
      time
    );
  }
}

export class SenderKeyDistributionMessage {
  private readonly nativeHandle: SignalClient.SenderKeyDistributionMessage;

  _unsafeGetNativeHandle(): SignalClient.SenderKeyDistributionMessage {
    return this.nativeHandle;
  }

  private constructor(nativeHandle: SignalClient.SenderKeyDistributionMessage) {
    this.nativeHandle = nativeHandle;
  }

  static async create(
    name: SenderKeyName,
    store: SenderKeyStore
  ): Promise<SenderKeyDistributionMessage> {
    const handle = await SC.SenderKeyDistributionMessage_Create(
      name._unsafeGetNativeHandle(),
      store
    );
    return new SenderKeyDistributionMessage(handle);
  }

  static new(
    keyId: number,
    iteration: number,
    chainKey: Buffer,
    pk: PublicKey
  ): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      SC.SenderKeyDistributionMessage_New(
        keyId,
        iteration,
        chainKey,
        pk._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      SC.SenderKeyDistributionMessage_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return SC.SenderKeyDistributionMessage_Serialize(this.nativeHandle);
  }

  chainKey(): Buffer {
    return SC.SenderKeyDistributionMessage_GetChainKey(this.nativeHandle);
  }

  iteration(): number {
    return SC.SenderKeyDistributionMessage_GetIteration(this.nativeHandle);
  }

  id(): number {
    return SC.SenderKeyDistributionMessage_GetId(this.nativeHandle);
  }
}

export async function processSenderKeyDistributionMessage(
  name: SenderKeyName,
  message: SenderKeyDistributionMessage,
  store: SenderKeyStore
): Promise<void> {
  await SC.SenderKeyDistributionMessage_Process(
    name._unsafeGetNativeHandle(),
    message._unsafeGetNativeHandle(),
    store
  );
}

export class SenderKeyMessage {
  private readonly nativeHandle: SignalClient.SenderKeyMessage;

  private constructor(nativeHandle: SignalClient.SenderKeyMessage) {
    this.nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    iteration: number,
    ciphertext: Buffer,
    pk: PrivateKey
  ): SenderKeyMessage {
    return new SenderKeyMessage(
      SC.SenderKeyMessage_New(
        keyId,
        iteration,
        ciphertext,
        pk._unsafeGetNativeHandle()
      )
    );
  }

  static deserialize(buffer: Buffer): SenderKeyMessage {
    return new SenderKeyMessage(SC.SenderKeyMessage_Deserialize(buffer));
  }

  serialize(): Buffer {
    return SC.SenderKeyMessage_Serialize(this.nativeHandle);
  }

  ciphertext(): Buffer {
    return SC.SenderKeyMessage_GetCipherText(this.nativeHandle);
  }

  iteration(): number {
    return SC.SenderKeyMessage_GetIteration(this.nativeHandle);
  }

  keyId(): number {
    return SC.SenderKeyMessage_GetKeyId(this.nativeHandle);
  }

  verifySignature(key: PublicKey): boolean {
    return SC.SenderKeyMessage_VerifySignature(
      this.nativeHandle,
      key._unsafeGetNativeHandle()
    );
  }
}

export class UnidentifiedSenderMessageContent {
  private readonly nativeHandle: SignalClient.UnidentifiedSenderMessageContent;

  private constructor(
    nativeHandle: SignalClient.UnidentifiedSenderMessageContent
  ) {
    this.nativeHandle = nativeHandle;
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
    return SC.UnidentifiedSenderMessageContent_Serialize(this.nativeHandle);
  }

  contents(): Buffer {
    return SC.UnidentifiedSenderMessageContent_GetContents(this.nativeHandle);
  }

  msgType(): number {
    return SC.UnidentifiedSenderMessageContent_GetMsgType(this.nativeHandle);
  }

  senderCertificate(): SenderCertificate {
    return SenderCertificate._fromNativeHandle(
      SC.UnidentifiedSenderMessageContent_GetSenderCert(this.nativeHandle)
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
      return sess._unsafeGetNativeHandle();
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
    return key._unsafeGetNativeHandle();
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
      return key._unsafeGetNativeHandle();
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
    return pk._unsafeGetNativeHandle();
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
    return pk._unsafeGetNativeHandle();
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
      return skr._unsafeGetNativeHandle();
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
  return SC.GroupCipher_Encrypt(name._unsafeGetNativeHandle(), store, message);
}

export async function groupDecrypt(
  name: SenderKeyName,
  store: SenderKeyStore,
  message: Buffer
): Promise<Buffer> {
  return SC.GroupCipher_Decrypt(name._unsafeGetNativeHandle(), store, message);
}

export class SealedSenderDecryptionResult {
  private readonly nativeHandle: SignalClient.SealedSenderDecryptionResult;

  private constructor(nativeHandle: SignalClient.SealedSenderDecryptionResult) {
    this.nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.SealedSenderDecryptionResult
  ): SealedSenderDecryptionResult {
    return new SealedSenderDecryptionResult(nativeHandle);
  }

  message(): Buffer {
    return SC.SealedSenderDecryptionResult_Message(this.nativeHandle);
  }

  senderE164(): string | null {
    return SC.SealedSenderDecryptionResult_GetSenderE164(this.nativeHandle);
  }

  senderUuid(): string {
    return SC.SealedSenderDecryptionResult_GetSenderUuid(this.nativeHandle);
  }

  deviceId(): number {
    return SC.SealedSenderDecryptionResult_GetDeviceId(this.nativeHandle);
  }
}

export class CiphertextMessage {
  private readonly nativeHandle: SignalClient.CiphertextMessage;

  private constructor(nativeHandle: SignalClient.CiphertextMessage) {
    this.nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: SignalClient.CiphertextMessage
  ): CiphertextMessage {
    return new CiphertextMessage(nativeHandle);
  }

  serialize(): Buffer {
    return SC.CiphertextMessage_Serialize(this.nativeHandle);
  }

  type(): number {
    return SC.CiphertextMessage_Type(this.nativeHandle);
  }
}

export function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<void> {
  return SC.SessionBuilder_ProcessPreKeyBundle(
    bundle._unsafeGetNativeHandle(),
    address._unsafeGetNativeHandle(),
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
      address._unsafeGetNativeHandle(),
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
    message._unsafeGetNativeHandle(),
    address._unsafeGetNativeHandle(),
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
    message._unsafeGetNativeHandle(),
    address._unsafeGetNativeHandle(),
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
    message,
    address._unsafeGetNativeHandle(),
    senderCert._unsafeGetNativeHandle(),
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
    trustRoot._unsafeGetNativeHandle(),
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
