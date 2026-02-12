//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

export type Uuid = Uint8Array;

/// A Native.Timestamp may be measured in seconds or in milliseconds;
/// what's important is that it's an integer less than Number.MAX_SAFE_INTEGER.
export type Timestamp = number;

// Rust code produces or consumes values that conform to these interface
// definitions. They must be kept in sync to prevent bridging errors.

export type LookupResponse = {
  entries: Map<string, LookupResponseEntry>;
  debugPermitsUsed: number;
};

export type LookupResponseEntry = {
  readonly aci: string | undefined;
  readonly pni: string | undefined;
};

export type ChatResponse = {
  status: number;
  message: string | undefined;
  headers: ReadonlyArray<[string, string]>;
  body: Uint8Array | undefined;
};

export type ChatServiceDebugInfo = {
  ipType: number;
  durationMillis: number;
  connectionInfo: string;
};

export type ResponseAndDebugInfo = {
  response: ChatResponse;
  debugInfo: ChatServiceDebugInfo;
};

export type SealedSenderMultiRecipientMessageRecipient = {
  deviceIds: number[];
  registrationIds: number[];
  rangeOffset: number;
  rangeLen: number;
};

export type SealedSenderMultiRecipientMessage = {
  recipientMap: {
    [serviceId: string]: SealedSenderMultiRecipientMessageRecipient;
  };
  excludedRecipients: string[];
  offsetOfSharedData: number;
};

export enum IdentityChange {
  // This must be kept in sync with the Rust enum of the same name.
  NewOrUnchanged = 0,
  ReplacedExisting = 1,
}

export type IdentityKeyStore = {
  _getIdentityKey: () => Promise<PrivateKey>;
  _getLocalRegistrationId: () => Promise<number>;
  _saveIdentity: (
    name: ProtocolAddress,
    key: PublicKey
  ) => Promise<IdentityChange>;
  _isTrustedIdentity: (
    name: ProtocolAddress,
    key: PublicKey,
    sending: boolean
  ) => Promise<boolean>;
  _getIdentity: (name: ProtocolAddress) => Promise<PublicKey | null>;
};

export type SessionStore = {
  _saveSession: (addr: ProtocolAddress, record: SessionRecord) => Promise<void>;
  _getSession: (addr: ProtocolAddress) => Promise<SessionRecord | null>;
};

export type PreKeyStore = {
  _savePreKey: (preKeyId: number, record: PreKeyRecord) => Promise<void>;
  _getPreKey: (preKeyId: number) => Promise<PreKeyRecord>;
  _removePreKey: (preKeyId: number) => Promise<void>;
};

export type SignedPreKeyStore = {
  _saveSignedPreKey: (
    signedPreKeyId: number,
    record: SignedPreKeyRecord
  ) => Promise<void>;
  _getSignedPreKey: (signedPreKeyId: number) => Promise<SignedPreKeyRecord>;
};

export type KyberPreKeyStore = {
  _saveKyberPreKey: (
    kyberPreKeyId: number,
    record: KyberPreKeyRecord
  ) => Promise<void>;
  _getKyberPreKey: (kyberPreKeyId: number) => Promise<KyberPreKeyRecord>;
  _markKyberPreKeyUsed: (
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKey: PublicKey
  ) => Promise<void>;
};

export type SenderKeyStore = {
  _saveSenderKey: (
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord
  ) => Promise<void>;
  _getSenderKey: (
    sender: ProtocolAddress,
    distributionId: Uuid
  ) => Promise<SenderKeyRecord | null>;
};

export type InputStream = {
  _read: (amount: number) => Promise<Uint8Array>;
  _skip: (amount: number) => Promise<void>;
};

export type SyncInputStream = Uint8Array;

export type ChallengeOption = 'pushChallenge' | 'captcha';

export type RegistrationPushTokenType = 'apn' | 'fcm';

export type RegistrationCreateSessionRequest = {
  number: string;
  push_token?: string;
  push_token_type?: RegistrationPushTokenType;
  mcc?: string;
  mnc?: string;
};

export type RegisterResponseBadge = {
  id: string;
  visible: boolean;
  expirationSeconds: number;
};

export type CheckSvr2CredentialsResponse = Map<
  string,
  'match' | 'no-match' | 'invalid'
>;

export type SignedPublicPreKey = {
  keyId: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
};

export type Wrapper<T> = Readonly<{
  _nativeHandle: T;
}>;

export type MessageBackupValidationOutcome = {
  errorMessage: string | null;
  unknownFieldMessages: Array<string>;
};

export type BackupJsonFrameError = {
  message: string;
  unknownFields: string[];
};

export type BackupJsonFrameResult = {
  line?: string;
  error?: BackupJsonFrameError;
};

export type JsonFrameExportResult = BackupJsonFrameResult;

export type AccountEntropyPool = string;

export type CancellablePromise<T> = Promise<T> & {
  _cancellationToken: bigint;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type Serialized<T> = Uint8Array;

type ConnectChatBridge = Wrapper<ConnectionManager>;
type TestingFutureCancellationGuard = Wrapper<TestingFutureCancellationCounter>;

// React Native: access JSI-installed global instead of node-gyp-build
declare const global: { __libsignal_native: NativeFunctions };

function getNativeModule(): NativeFunctions {
  const native = (globalThis as any).__libsignal_native;
  if (!native) {
    throw new Error(
      'libsignal native module not installed. ' +
      'Did you call LibsignalModule.install() from Java/ObjC?'
    );
  }
  return native;
}

type NativeFunctions = {
  registerErrors: (errorsModule: Record<string, unknown>) => void;
  initLogger: (maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void) => void
  SealedSenderMultiRecipientMessage_Parse: (buffer: Uint8Array) => SealedSenderMultiRecipientMessage;
  MinidumpToJSONString: (buffer: Uint8Array) => string;
  Aes256GcmSiv_New: (key: Uint8Array) => Aes256GcmSiv;
  Aes256GcmSiv_Encrypt: (aesGcmSivObj: Wrapper<Aes256GcmSiv>, ptext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array) => Uint8Array;
  Aes256GcmSiv_Decrypt: (aesGcmSiv: Wrapper<Aes256GcmSiv>, ctext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array) => Uint8Array;
  PublicKey_HpkeSeal: (pk: Wrapper<PublicKey>, plaintext: Uint8Array, info: Uint8Array, associatedData: Uint8Array) => Uint8Array;
  PrivateKey_HpkeOpen: (sk: Wrapper<PrivateKey>, ciphertext: Uint8Array, info: Uint8Array, associatedData: Uint8Array) => Uint8Array;
  HKDF_DeriveSecrets: (outputLength: number, ikm: Uint8Array, label: Uint8Array | null, salt: Uint8Array | null) => Uint8Array;
  ServiceId_ServiceIdBinary: (value: Uint8Array) => Uint8Array;
  ServiceId_ServiceIdString: (value: Uint8Array) => string;
  ServiceId_ServiceIdLog: (value: Uint8Array) => string;
  ServiceId_ParseFromServiceIdBinary: (input: Uint8Array) => Uint8Array;
  ServiceId_ParseFromServiceIdString: (input: string) => Uint8Array;
  ProtocolAddress_New: (name: string, deviceId: number) => ProtocolAddress;
  PublicKey_Deserialize: (data: Uint8Array) => PublicKey;
  PublicKey_Serialize: (obj: Wrapper<PublicKey>) => Uint8Array;
  PublicKey_GetPublicKeyBytes: (obj: Wrapper<PublicKey>) => Uint8Array;
  ProtocolAddress_DeviceId: (obj: Wrapper<ProtocolAddress>) => number;
  ProtocolAddress_Name: (obj: Wrapper<ProtocolAddress>) => string;
  PublicKey_Equals: (lhs: Wrapper<PublicKey>, rhs: Wrapper<PublicKey>) => boolean;
  PublicKey_Verify: (key: Wrapper<PublicKey>, message: Uint8Array, signature: Uint8Array) => boolean;
  PrivateKey_Deserialize: (data: Uint8Array) => PrivateKey;
  PrivateKey_Serialize: (obj: Wrapper<PrivateKey>) => Uint8Array;
  PrivateKey_Generate: () => PrivateKey;
  PrivateKey_GetPublicKey: (k: Wrapper<PrivateKey>) => PublicKey;
  PrivateKey_Sign: (key: Wrapper<PrivateKey>, message: Uint8Array) => Uint8Array;
  PrivateKey_Agree: (privateKey: Wrapper<PrivateKey>, publicKey: Wrapper<PublicKey>) => Uint8Array;
  KyberPublicKey_Serialize: (obj: Wrapper<KyberPublicKey>) => Uint8Array;
  KyberPublicKey_Deserialize: (data: Uint8Array) => KyberPublicKey;
  KyberSecretKey_Serialize: (obj: Wrapper<KyberSecretKey>) => Uint8Array;
  KyberSecretKey_Deserialize: (data: Uint8Array) => KyberSecretKey;
  KyberPublicKey_Equals: (lhs: Wrapper<KyberPublicKey>, rhs: Wrapper<KyberPublicKey>) => boolean;
  KyberKeyPair_Generate: () => KyberKeyPair;
  KyberKeyPair_GetPublicKey: (keyPair: Wrapper<KyberKeyPair>) => KyberPublicKey;
  KyberKeyPair_GetSecretKey: (keyPair: Wrapper<KyberKeyPair>) => KyberSecretKey;
  IdentityKeyPair_Serialize: (publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>) => Uint8Array;
  IdentityKeyPair_Deserialize: (input: Uint8Array) => [PublicKey, PrivateKey];
  IdentityKeyPair_SignAlternateIdentity: (publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>, otherIdentity: Wrapper<PublicKey>) => Uint8Array;
  IdentityKey_VerifyAlternateIdentity: (publicKey: Wrapper<PublicKey>, otherIdentity: Wrapper<PublicKey>, signature: Uint8Array) => boolean;
  Fingerprint_New: (iterations: number, version: number, localIdentifier: Uint8Array, localKey: Wrapper<PublicKey>, remoteIdentifier: Uint8Array, remoteKey: Wrapper<PublicKey>) => Fingerprint;
  Fingerprint_ScannableEncoding: (obj: Wrapper<Fingerprint>) => Uint8Array;
  Fingerprint_DisplayString: (obj: Wrapper<Fingerprint>) => string;
  ScannableFingerprint_Compare: (fprint1: Uint8Array, fprint2: Uint8Array) => boolean;
  SignalMessage_Deserialize: (data: Uint8Array) => SignalMessage;
  SignalMessage_GetBody: (obj: Wrapper<SignalMessage>) => Uint8Array;
  SignalMessage_GetSerialized: (obj: Wrapper<SignalMessage>) => Uint8Array;
  SignalMessage_GetCounter: (obj: Wrapper<SignalMessage>) => number;
  SignalMessage_GetMessageVersion: (obj: Wrapper<SignalMessage>) => number;
  SignalMessage_GetPqRatchet: (msg: Wrapper<SignalMessage>) => Uint8Array;
  SignalMessage_New: (messageVersion: number, macKey: Uint8Array, senderRatchetKey: Wrapper<PublicKey>, counter: number, previousCounter: number, ciphertext: Uint8Array, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, pqRatchet: Uint8Array) => SignalMessage;
  SignalMessage_VerifyMac: (msg: Wrapper<SignalMessage>, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, macKey: Uint8Array) => boolean;
  PreKeySignalMessage_New: (messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: Wrapper<PublicKey>, identityKey: Wrapper<PublicKey>, signalMessage: Wrapper<SignalMessage>) => PreKeySignalMessage;
  PreKeySignalMessage_Deserialize: (data: Uint8Array) => PreKeySignalMessage;
  PreKeySignalMessage_Serialize: (obj: Wrapper<PreKeySignalMessage>) => Uint8Array;
  PreKeySignalMessage_GetRegistrationId: (obj: Wrapper<PreKeySignalMessage>) => number;
  PreKeySignalMessage_GetSignedPreKeyId: (obj: Wrapper<PreKeySignalMessage>) => number;
  PreKeySignalMessage_GetPreKeyId: (obj: Wrapper<PreKeySignalMessage>) => number | null;
  PreKeySignalMessage_GetVersion: (obj: Wrapper<PreKeySignalMessage>) => number;
  SenderKeyMessage_Deserialize: (data: Uint8Array) => SenderKeyMessage;
  SenderKeyMessage_GetCipherText: (obj: Wrapper<SenderKeyMessage>) => Uint8Array;
  SenderKeyMessage_Serialize: (obj: Wrapper<SenderKeyMessage>) => Uint8Array;
  SenderKeyMessage_GetDistributionId: (obj: Wrapper<SenderKeyMessage>) => Uuid;
  SenderKeyMessage_GetChainId: (obj: Wrapper<SenderKeyMessage>) => number;
  SenderKeyMessage_GetIteration: (obj: Wrapper<SenderKeyMessage>) => number;
  SenderKeyMessage_New: (messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, ciphertext: Uint8Array, pk: Wrapper<PrivateKey>) => SenderKeyMessage;
  SenderKeyMessage_VerifySignature: (skm: Wrapper<SenderKeyMessage>, pubkey: Wrapper<PublicKey>) => boolean;
  SenderKeyDistributionMessage_Deserialize: (data: Uint8Array) => SenderKeyDistributionMessage;
  SenderKeyDistributionMessage_GetChainKey: (obj: Wrapper<SenderKeyDistributionMessage>) => Uint8Array;
  SenderKeyDistributionMessage_Serialize: (obj: Wrapper<SenderKeyDistributionMessage>) => Uint8Array;
  SenderKeyDistributionMessage_GetDistributionId: (obj: Wrapper<SenderKeyDistributionMessage>) => Uuid;
  SenderKeyDistributionMessage_GetChainId: (obj: Wrapper<SenderKeyDistributionMessage>) => number;
  SenderKeyDistributionMessage_GetIteration: (obj: Wrapper<SenderKeyDistributionMessage>) => number;
  SenderKeyDistributionMessage_New: (messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, chainkey: Uint8Array, pk: Wrapper<PublicKey>) => SenderKeyDistributionMessage;
  DecryptionErrorMessage_Deserialize: (data: Uint8Array) => DecryptionErrorMessage;
  DecryptionErrorMessage_GetTimestamp: (obj: Wrapper<DecryptionErrorMessage>) => Timestamp;
  DecryptionErrorMessage_GetDeviceId: (obj: Wrapper<DecryptionErrorMessage>) => number;
  DecryptionErrorMessage_Serialize: (obj: Wrapper<DecryptionErrorMessage>) => Uint8Array;
  DecryptionErrorMessage_GetRatchetKey: (m: Wrapper<DecryptionErrorMessage>) => PublicKey | null;
  DecryptionErrorMessage_ForOriginalMessage: (originalBytes: Uint8Array, originalType: number, originalTimestamp: Timestamp, originalSenderDeviceId: number) => DecryptionErrorMessage;
  DecryptionErrorMessage_ExtractFromSerializedContent: (bytes: Uint8Array) => DecryptionErrorMessage;
  PlaintextContent_Deserialize: (data: Uint8Array) => PlaintextContent;
  PlaintextContent_Serialize: (obj: Wrapper<PlaintextContent>) => Uint8Array;
  PlaintextContent_GetBody: (obj: Wrapper<PlaintextContent>) => Uint8Array;
  PlaintextContent_FromDecryptionErrorMessage: (m: Wrapper<DecryptionErrorMessage>) => PlaintextContent;
  PreKeyBundle_New: (registrationId: number, deviceId: number, prekeyId: number | null, prekey: Wrapper<PublicKey> | null, signedPrekeyId: number, signedPrekey: Wrapper<PublicKey>, signedPrekeySignature: Uint8Array, identityKey: Wrapper<PublicKey>, kyberPrekeyId: number, kyberPrekey: Wrapper<KyberPublicKey>, kyberPrekeySignature: Uint8Array) => PreKeyBundle;
  PreKeyBundle_GetIdentityKey: (p: Wrapper<PreKeyBundle>) => PublicKey;
  PreKeyBundle_GetSignedPreKeySignature: (obj: Wrapper<PreKeyBundle>) => Uint8Array;
  PreKeyBundle_GetKyberPreKeySignature: (obj: Wrapper<PreKeyBundle>) => Uint8Array;
  PreKeyBundle_GetRegistrationId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetDeviceId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetSignedPreKeyId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetKyberPreKeyId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetPreKeyId: (obj: Wrapper<PreKeyBundle>) => number | null;
  PreKeyBundle_GetPreKeyPublic: (obj: Wrapper<PreKeyBundle>) => PublicKey | null;
  PreKeyBundle_GetSignedPreKeyPublic: (obj: Wrapper<PreKeyBundle>) => PublicKey;
  PreKeyBundle_GetKyberPreKeyPublic: (bundle: Wrapper<PreKeyBundle>) => KyberPublicKey;
  SignedPreKeyRecord_Deserialize: (data: Uint8Array) => SignedPreKeyRecord;
  SignedPreKeyRecord_GetSignature: (obj: Wrapper<SignedPreKeyRecord>) => Uint8Array;
  SignedPreKeyRecord_Serialize: (obj: Wrapper<SignedPreKeyRecord>) => Uint8Array;
  SignedPreKeyRecord_GetId: (obj: Wrapper<SignedPreKeyRecord>) => number;
  SignedPreKeyRecord_GetTimestamp: (obj: Wrapper<SignedPreKeyRecord>) => Timestamp;
  SignedPreKeyRecord_GetPublicKey: (obj: Wrapper<SignedPreKeyRecord>) => PublicKey;
  SignedPreKeyRecord_GetPrivateKey: (obj: Wrapper<SignedPreKeyRecord>) => PrivateKey;
  KyberPreKeyRecord_Deserialize: (data: Uint8Array) => KyberPreKeyRecord;
  KyberPreKeyRecord_GetSignature: (obj: Wrapper<KyberPreKeyRecord>) => Uint8Array;
  KyberPreKeyRecord_Serialize: (obj: Wrapper<KyberPreKeyRecord>) => Uint8Array;
  KyberPreKeyRecord_GetId: (obj: Wrapper<KyberPreKeyRecord>) => number;
  KyberPreKeyRecord_GetTimestamp: (obj: Wrapper<KyberPreKeyRecord>) => Timestamp;
  KyberPreKeyRecord_GetPublicKey: (obj: Wrapper<KyberPreKeyRecord>) => KyberPublicKey;
  KyberPreKeyRecord_GetSecretKey: (obj: Wrapper<KyberPreKeyRecord>) => KyberSecretKey;
  KyberPreKeyRecord_GetKeyPair: (obj: Wrapper<KyberPreKeyRecord>) => KyberKeyPair;
  SignedPreKeyRecord_New: (id: number, timestamp: Timestamp, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>, signature: Uint8Array) => SignedPreKeyRecord;
  KyberPreKeyRecord_New: (id: number, timestamp: Timestamp, keyPair: Wrapper<KyberKeyPair>, signature: Uint8Array) => KyberPreKeyRecord;
  PreKeyRecord_Deserialize: (data: Uint8Array) => PreKeyRecord;
  PreKeyRecord_Serialize: (obj: Wrapper<PreKeyRecord>) => Uint8Array;
  PreKeyRecord_GetId: (obj: Wrapper<PreKeyRecord>) => number;
  PreKeyRecord_GetPublicKey: (obj: Wrapper<PreKeyRecord>) => PublicKey;
  PreKeyRecord_GetPrivateKey: (obj: Wrapper<PreKeyRecord>) => PrivateKey;
  PreKeyRecord_New: (id: number, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>) => PreKeyRecord;
  SenderKeyRecord_Deserialize: (data: Uint8Array) => SenderKeyRecord;
  SenderKeyRecord_Serialize: (obj: Wrapper<SenderKeyRecord>) => Uint8Array;
  ServerCertificate_Deserialize: (data: Uint8Array) => ServerCertificate;
  ServerCertificate_GetSerialized: (obj: Wrapper<ServerCertificate>) => Uint8Array;
  ServerCertificate_GetCertificate: (obj: Wrapper<ServerCertificate>) => Uint8Array;
  ServerCertificate_GetSignature: (obj: Wrapper<ServerCertificate>) => Uint8Array;
  ServerCertificate_GetKeyId: (obj: Wrapper<ServerCertificate>) => number;
  ServerCertificate_GetKey: (obj: Wrapper<ServerCertificate>) => PublicKey;
  ServerCertificate_New: (keyId: number, serverKey: Wrapper<PublicKey>, trustRoot: Wrapper<PrivateKey>) => ServerCertificate;
  SenderCertificate_Deserialize: (data: Uint8Array) => SenderCertificate;
  SenderCertificate_GetSerialized: (obj: Wrapper<SenderCertificate>) => Uint8Array;
  SenderCertificate_GetCertificate: (obj: Wrapper<SenderCertificate>) => Uint8Array;
  SenderCertificate_GetSignature: (obj: Wrapper<SenderCertificate>) => Uint8Array;
  SenderCertificate_GetSenderUuid: (obj: Wrapper<SenderCertificate>) => string;
  SenderCertificate_GetSenderE164: (obj: Wrapper<SenderCertificate>) => string | null;
  SenderCertificate_GetExpiration: (obj: Wrapper<SenderCertificate>) => Timestamp;
  SenderCertificate_GetDeviceId: (obj: Wrapper<SenderCertificate>) => number;
  SenderCertificate_GetKey: (obj: Wrapper<SenderCertificate>) => PublicKey;
  SenderCertificate_Validate: (cert: Wrapper<SenderCertificate>, trustRoots: Wrapper<PublicKey>[], time: Timestamp) => boolean;
  SenderCertificate_GetServerCertificate: (cert: Wrapper<SenderCertificate>) => ServerCertificate;
  SenderCertificate_New: (senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: Wrapper<PublicKey>, expiration: Timestamp, signerCert: Wrapper<ServerCertificate>, signerKey: Wrapper<PrivateKey>) => SenderCertificate;
  UnidentifiedSenderMessageContent_Deserialize: (data: Uint8Array) => UnidentifiedSenderMessageContent;
  UnidentifiedSenderMessageContent_Serialize: (obj: Wrapper<UnidentifiedSenderMessageContent>) => Uint8Array;
  UnidentifiedSenderMessageContent_GetContents: (obj: Wrapper<UnidentifiedSenderMessageContent>) => Uint8Array;
  UnidentifiedSenderMessageContent_GetGroupId: (obj: Wrapper<UnidentifiedSenderMessageContent>) => Uint8Array | null;
  UnidentifiedSenderMessageContent_GetSenderCert: (m: Wrapper<UnidentifiedSenderMessageContent>) => SenderCertificate;
  UnidentifiedSenderMessageContent_GetMsgType: (m: Wrapper<UnidentifiedSenderMessageContent>) => number;
  UnidentifiedSenderMessageContent_GetContentHint: (m: Wrapper<UnidentifiedSenderMessageContent>) => number;
  UnidentifiedSenderMessageContent_New: (message: Wrapper<CiphertextMessage>, sender: Wrapper<SenderCertificate>, contentHint: number, groupId: Uint8Array | null) => UnidentifiedSenderMessageContent;
  CiphertextMessage_Type: (msg: Wrapper<CiphertextMessage>) => number;
  CiphertextMessage_Serialize: (obj: Wrapper<CiphertextMessage>) => Uint8Array;
  CiphertextMessage_FromPlaintextContent: (m: Wrapper<PlaintextContent>) => CiphertextMessage;
  SessionRecord_ArchiveCurrentState: (sessionRecord: Wrapper<SessionRecord>) => void;
  SessionRecord_HasUsableSenderChain: (s: Wrapper<SessionRecord>, now: Timestamp) => boolean;
  SessionRecord_CurrentRatchetKeyMatches: (s: Wrapper<SessionRecord>, key: Wrapper<PublicKey>) => boolean;
  SessionRecord_Deserialize: (data: Uint8Array) => SessionRecord;
  SessionRecord_Serialize: (obj: Wrapper<SessionRecord>) => Uint8Array;
  SessionRecord_GetLocalRegistrationId: (obj: Wrapper<SessionRecord>) => number;
  SessionRecord_GetRemoteRegistrationId: (obj: Wrapper<SessionRecord>) => number;
  SealedSenderDecryptionResult_GetSenderUuid: (obj: Wrapper<SealedSenderDecryptionResult>) => string;
  SealedSenderDecryptionResult_GetSenderE164: (obj: Wrapper<SealedSenderDecryptionResult>) => string | null;
  SealedSenderDecryptionResult_GetDeviceId: (obj: Wrapper<SealedSenderDecryptionResult>) => number;
  SealedSenderDecryptionResult_Message: (obj: Wrapper<SealedSenderDecryptionResult>) => Uint8Array;
  SessionBuilder_ProcessPreKeyBundle: (bundle: Wrapper<PreKeyBundle>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp) => Promise<void>;
  SessionCipher_EncryptMessage: (ptext: Uint8Array, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp) => Promise<CiphertextMessage>;
  SessionCipher_DecryptSignalMessage: (message: Wrapper<SignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore) => Promise<Uint8Array>;
  SessionCipher_DecryptPreKeySignalMessage: (message: Wrapper<PreKeySignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore) => Promise<Uint8Array>;
  SealedSender_Encrypt: (destination: Wrapper<ProtocolAddress>, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore) => Promise<Uint8Array>;
  SealedSender_MultiRecipientEncrypt: (recipients: Wrapper<ProtocolAddress>[], recipientSessions: Wrapper<SessionRecord>[], excludedRecipients: Uint8Array, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore) => Promise<Uint8Array>;
  SealedSender_MultiRecipientMessageForSingleRecipient: (encodedMultiRecipientMessage: Uint8Array) => Uint8Array;
  SealedSender_DecryptToUsmc: (ctext: Uint8Array, identityStore: IdentityKeyStore) => Promise<UnidentifiedSenderMessageContent>;
  SealedSender_DecryptMessage: (message: Uint8Array, trustRoot: Wrapper<PublicKey>, timestamp: Timestamp, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore) => Promise<SealedSenderDecryptionResult>;
  SenderKeyDistributionMessage_Create: (sender: Wrapper<ProtocolAddress>, distributionId: Uuid, store: SenderKeyStore) => Promise<SenderKeyDistributionMessage>;
  SenderKeyDistributionMessage_Process: (sender: Wrapper<ProtocolAddress>, senderKeyDistributionMessage: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore) => Promise<void>;
  GroupCipher_EncryptMessage: (sender: Wrapper<ProtocolAddress>, distributionId: Uuid, message: Uint8Array, store: SenderKeyStore) => Promise<CiphertextMessage>;
  GroupCipher_DecryptMessage: (sender: Wrapper<ProtocolAddress>, message: Uint8Array, store: SenderKeyStore) => Promise<Uint8Array>;
  Cds2ClientState_New: (mrenclave: Uint8Array, attestationMsg: Uint8Array, currentTimestamp: Timestamp) => SgxClientState;
  HsmEnclaveClient_New: (trustedPublicKey: Uint8Array, trustedCodeHashes: Uint8Array) => HsmEnclaveClient;
  HsmEnclaveClient_CompleteHandshake: (cli: Wrapper<HsmEnclaveClient>, handshakeReceived: Uint8Array) => void;
  HsmEnclaveClient_EstablishedSend: (cli: Wrapper<HsmEnclaveClient>, plaintextToSend: Uint8Array) => Uint8Array;
  HsmEnclaveClient_EstablishedRecv: (cli: Wrapper<HsmEnclaveClient>, receivedCiphertext: Uint8Array) => Uint8Array;
  HsmEnclaveClient_InitialRequest: (obj: Wrapper<HsmEnclaveClient>) => Uint8Array;
  SgxClientState_InitialRequest: (obj: Wrapper<SgxClientState>) => Uint8Array;
  SgxClientState_CompleteHandshake: (cli: Wrapper<SgxClientState>, handshakeReceived: Uint8Array) => void;
  SgxClientState_EstablishedSend: (cli: Wrapper<SgxClientState>, plaintextToSend: Uint8Array) => Uint8Array;
  SgxClientState_EstablishedRecv: (cli: Wrapper<SgxClientState>, receivedCiphertext: Uint8Array) => Uint8Array;
  ExpiringProfileKeyCredential_CheckValidContents: (buffer: Uint8Array) => void;
  ExpiringProfileKeyCredentialResponse_CheckValidContents: (buffer: Uint8Array) => void;
  GroupMasterKey_CheckValidContents: (buffer: Uint8Array) => void;
  GroupPublicParams_CheckValidContents: (buffer: Uint8Array) => void;
  GroupSecretParams_CheckValidContents: (buffer: Uint8Array) => void;
  ProfileKey_CheckValidContents: (buffer: Uint8Array) => void;
  ProfileKeyCiphertext_CheckValidContents: (buffer: Uint8Array) => void;
  ProfileKeyCommitment_CheckValidContents: (buffer: Uint8Array) => void;
  ProfileKeyCredentialRequest_CheckValidContents: (buffer: Uint8Array) => void;
  ProfileKeyCredentialRequestContext_CheckValidContents: (buffer: Uint8Array) => void;
  ReceiptCredential_CheckValidContents: (buffer: Uint8Array) => void;
  ReceiptCredentialPresentation_CheckValidContents: (buffer: Uint8Array) => void;
  ReceiptCredentialRequest_CheckValidContents: (buffer: Uint8Array) => void;
  ReceiptCredentialRequestContext_CheckValidContents: (buffer: Uint8Array) => void;
  ReceiptCredentialResponse_CheckValidContents: (buffer: Uint8Array) => void;
  UuidCiphertext_CheckValidContents: (buffer: Uint8Array) => void;
  ServerPublicParams_Deserialize: (buffer: Uint8Array) => ServerPublicParams;
  ServerPublicParams_Serialize: (handle: Wrapper<ServerPublicParams>) => Uint8Array;
  ServerSecretParams_Deserialize: (buffer: Uint8Array) => ServerSecretParams;
  ServerSecretParams_Serialize: (handle: Wrapper<ServerSecretParams>) => Uint8Array;
  ProfileKey_GetCommitment: (profileKey: Serialized<ProfileKey>, userId: Uint8Array) => Serialized<ProfileKeyCommitment>;
  ProfileKey_GetProfileKeyVersion: (profileKey: Serialized<ProfileKey>, userId: Uint8Array) => Uint8Array;
  ProfileKey_DeriveAccessKey: (profileKey: Serialized<ProfileKey>) => Uint8Array;
  GroupSecretParams_GenerateDeterministic: (randomness: Uint8Array) => Serialized<GroupSecretParams>;
  GroupSecretParams_DeriveFromMasterKey: (masterKey: Serialized<GroupMasterKey>) => Serialized<GroupSecretParams>;
  GroupSecretParams_GetMasterKey: (params: Serialized<GroupSecretParams>) => Serialized<GroupMasterKey>;
  GroupSecretParams_GetPublicParams: (params: Serialized<GroupSecretParams>) => Serialized<GroupPublicParams>;
  GroupSecretParams_EncryptServiceId: (params: Serialized<GroupSecretParams>, serviceId: Uint8Array) => Serialized<UuidCiphertext>;
  GroupSecretParams_DecryptServiceId: (params: Serialized<GroupSecretParams>, ciphertext: Serialized<UuidCiphertext>) => Uint8Array;
  GroupSecretParams_EncryptProfileKey: (params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKey>, userId: Uint8Array) => Serialized<ProfileKeyCiphertext>;
  GroupSecretParams_DecryptProfileKey: (params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKeyCiphertext>, userId: Uint8Array) => Serialized<ProfileKey>;
  GroupSecretParams_EncryptBlobWithPaddingDeterministic: (params: Serialized<GroupSecretParams>, randomness: Uint8Array, plaintext: Uint8Array, paddingLen: number) => Uint8Array;
  GroupSecretParams_DecryptBlobWithPadding: (params: Serialized<GroupSecretParams>, ciphertext: Uint8Array) => Uint8Array;
  ServerSecretParams_GenerateDeterministic: (randomness: Uint8Array) => ServerSecretParams;
  ServerSecretParams_GetPublicParams: (params: Wrapper<ServerSecretParams>) => ServerPublicParams;
  ServerSecretParams_SignDeterministic: (params: Wrapper<ServerSecretParams>, randomness: Uint8Array, message: Uint8Array) => Uint8Array;
  ServerPublicParams_GetEndorsementPublicKey: (params: Wrapper<ServerPublicParams>) => Uint8Array;
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId: (params: Wrapper<ServerPublicParams>, aci: Uint8Array, pni: Uint8Array, redemptionTime: Timestamp, authCredentialWithPniResponseBytes: Uint8Array) => Uint8Array;
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic: (serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, groupSecretParams: Serialized<GroupSecretParams>, authCredentialWithPniBytes: Uint8Array) => Uint8Array;
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic: (serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, userId: Uint8Array, profileKey: Serialized<ProfileKey>) => Serialized<ProfileKeyCredentialRequestContext>;
  ServerPublicParams_ReceiveExpiringProfileKeyCredential: (serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ProfileKeyCredentialRequestContext>, response: Serialized<ExpiringProfileKeyCredentialResponse>, currentTimeInSeconds: Timestamp) => Serialized<ExpiringProfileKeyCredential>;
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic: (serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, groupSecretParams: Serialized<GroupSecretParams>, profileKeyCredential: Serialized<ExpiringProfileKeyCredential>) => Uint8Array;
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic: (serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, receiptSerial: Uint8Array) => Serialized<ReceiptCredentialRequestContext>;
  ServerPublicParams_ReceiveReceiptCredential: (serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ReceiptCredentialRequestContext>, response: Serialized<ReceiptCredentialResponse>) => Serialized<ReceiptCredential>;
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic: (serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, receiptCredential: Serialized<ReceiptCredential>) => Serialized<ReceiptCredentialPresentation>;
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic: (serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, aci: Uint8Array, pni: Uint8Array, redemptionTime: Timestamp) => Uint8Array;
  AuthCredentialWithPni_CheckValidContents: (bytes: Uint8Array) => void;
  AuthCredentialWithPniResponse_CheckValidContents: (bytes: Uint8Array) => void;
  ServerSecretParams_VerifyAuthCredentialPresentation: (serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Uint8Array, currentTimeInSeconds: Timestamp) => void;
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic: (serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, request: Serialized<ProfileKeyCredentialRequest>, userId: Uint8Array, commitment: Serialized<ProfileKeyCommitment>, expirationInSeconds: Timestamp) => Serialized<ExpiringProfileKeyCredentialResponse>;
  ServerSecretParams_VerifyProfileKeyCredentialPresentation: (serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Uint8Array, currentTimeInSeconds: Timestamp) => void;
  ServerSecretParams_IssueReceiptCredentialDeterministic: (serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, request: Serialized<ReceiptCredentialRequest>, receiptExpirationTime: Timestamp, receiptLevel: bigint) => Serialized<ReceiptCredentialResponse>;
  ServerSecretParams_VerifyReceiptCredentialPresentation: (serverSecretParams: Wrapper<ServerSecretParams>, presentation: Serialized<ReceiptCredentialPresentation>) => void;
  GroupPublicParams_GetGroupIdentifier: (groupPublicParams: Serialized<GroupPublicParams>) => Uint8Array;
  ServerPublicParams_VerifySignature: (serverPublicParams: Wrapper<ServerPublicParams>, message: Uint8Array, notarySignature: Uint8Array) => void;
  AuthCredentialPresentation_CheckValidContents: (presentationBytes: Uint8Array) => void;
  AuthCredentialPresentation_GetUuidCiphertext: (presentationBytes: Uint8Array) => Serialized<UuidCiphertext>;
  AuthCredentialPresentation_GetPniCiphertext: (presentationBytes: Uint8Array) => Serialized<UuidCiphertext>;
  AuthCredentialPresentation_GetRedemptionTime: (presentationBytes: Uint8Array) => Timestamp;
  ProfileKeyCredentialRequestContext_GetRequest: (context: Serialized<ProfileKeyCredentialRequestContext>) => Serialized<ProfileKeyCredentialRequest>;
  ExpiringProfileKeyCredential_GetExpirationTime: (credential: Serialized<ExpiringProfileKeyCredential>) => Timestamp;
  ProfileKeyCredentialPresentation_CheckValidContents: (presentationBytes: Uint8Array) => void;
  ProfileKeyCredentialPresentation_GetUuidCiphertext: (presentationBytes: Uint8Array) => Serialized<UuidCiphertext>;
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext: (presentationBytes: Uint8Array) => Serialized<ProfileKeyCiphertext>;
  ReceiptCredentialRequestContext_GetRequest: (requestContext: Serialized<ReceiptCredentialRequestContext>) => Serialized<ReceiptCredentialRequest>;
  ReceiptCredential_GetReceiptExpirationTime: (receiptCredential: Serialized<ReceiptCredential>) => Timestamp;
  ReceiptCredential_GetReceiptLevel: (receiptCredential: Serialized<ReceiptCredential>) => bigint;
  ReceiptCredentialPresentation_GetReceiptExpirationTime: (presentation: Serialized<ReceiptCredentialPresentation>) => Timestamp;
  ReceiptCredentialPresentation_GetReceiptLevel: (presentation: Serialized<ReceiptCredentialPresentation>) => bigint;
  ReceiptCredentialPresentation_GetReceiptSerial: (presentation: Serialized<ReceiptCredentialPresentation>) => Uint8Array;
  GenericServerSecretParams_CheckValidContents: (paramsBytes: Uint8Array) => void;
  GenericServerSecretParams_GenerateDeterministic: (randomness: Uint8Array) => Uint8Array;
  GenericServerSecretParams_GetPublicParams: (paramsBytes: Uint8Array) => Uint8Array;
  GenericServerPublicParams_CheckValidContents: (paramsBytes: Uint8Array) => void;
  CallLinkSecretParams_CheckValidContents: (paramsBytes: Uint8Array) => void;
  CallLinkSecretParams_DeriveFromRootKey: (rootKey: Uint8Array) => Uint8Array;
  CallLinkSecretParams_GetPublicParams: (paramsBytes: Uint8Array) => Uint8Array;
  CallLinkSecretParams_DecryptUserId: (paramsBytes: Uint8Array, userId: Serialized<UuidCiphertext>) => Uint8Array;
  CallLinkSecretParams_EncryptUserId: (paramsBytes: Uint8Array, userId: Uint8Array) => Serialized<UuidCiphertext>;
  CallLinkPublicParams_CheckValidContents: (paramsBytes: Uint8Array) => void;
  CreateCallLinkCredentialRequestContext_CheckValidContents: (contextBytes: Uint8Array) => void;
  CreateCallLinkCredentialRequestContext_NewDeterministic: (roomId: Uint8Array, randomness: Uint8Array) => Uint8Array;
  CreateCallLinkCredentialRequestContext_GetRequest: (contextBytes: Uint8Array) => Uint8Array;
  CreateCallLinkCredentialRequest_CheckValidContents: (requestBytes: Uint8Array) => void;
  CreateCallLinkCredentialRequest_IssueDeterministic: (requestBytes: Uint8Array, userId: Uint8Array, timestamp: Timestamp, paramsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  CreateCallLinkCredentialResponse_CheckValidContents: (responseBytes: Uint8Array) => void;
  CreateCallLinkCredentialRequestContext_ReceiveResponse: (contextBytes: Uint8Array, responseBytes: Uint8Array, userId: Uint8Array, paramsBytes: Uint8Array) => Uint8Array;
  CreateCallLinkCredential_CheckValidContents: (paramsBytes: Uint8Array) => void;
  CreateCallLinkCredential_PresentDeterministic: (credentialBytes: Uint8Array, roomId: Uint8Array, userId: Uint8Array, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  CreateCallLinkCredentialPresentation_CheckValidContents: (presentationBytes: Uint8Array) => void;
  CreateCallLinkCredentialPresentation_Verify: (presentationBytes: Uint8Array, roomId: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array) => void;
  CallLinkAuthCredentialResponse_CheckValidContents: (responseBytes: Uint8Array) => void;
  CallLinkAuthCredentialResponse_IssueDeterministic: (userId: Uint8Array, redemptionTime: Timestamp, paramsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  CallLinkAuthCredentialResponse_Receive: (responseBytes: Uint8Array, userId: Uint8Array, redemptionTime: Timestamp, paramsBytes: Uint8Array) => Uint8Array;
  CallLinkAuthCredential_CheckValidContents: (credentialBytes: Uint8Array) => void;
  CallLinkAuthCredential_PresentDeterministic: (credentialBytes: Uint8Array, userId: Uint8Array, redemptionTime: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  CallLinkAuthCredentialPresentation_CheckValidContents: (presentationBytes: Uint8Array) => void;
  CallLinkAuthCredentialPresentation_Verify: (presentationBytes: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array) => void;
  CallLinkAuthCredentialPresentation_GetUserId: (presentationBytes: Uint8Array) => Serialized<UuidCiphertext>;
  BackupAuthCredentialRequestContext_New: (backupKey: Uint8Array, uuid: Uuid) => Uint8Array;
  BackupAuthCredentialRequestContext_CheckValidContents: (contextBytes: Uint8Array) => void;
  BackupAuthCredentialRequestContext_GetRequest: (contextBytes: Uint8Array) => Uint8Array;
  BackupAuthCredentialRequest_CheckValidContents: (requestBytes: Uint8Array) => void;
  BackupAuthCredentialRequest_IssueDeterministic: (requestBytes: Uint8Array, redemptionTime: Timestamp, backupLevel: number, credentialType: number, paramsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  BackupAuthCredentialResponse_CheckValidContents: (responseBytes: Uint8Array) => void;
  BackupAuthCredentialRequestContext_ReceiveResponse: (contextBytes: Uint8Array, responseBytes: Uint8Array, expectedRedemptionTime: Timestamp, paramsBytes: Uint8Array) => Uint8Array;
  BackupAuthCredential_CheckValidContents: (paramsBytes: Uint8Array) => void;
  BackupAuthCredential_GetBackupId: (credentialBytes: Uint8Array) => Uint8Array;
  BackupAuthCredential_GetBackupLevel: (credentialBytes: Uint8Array) => number;
  BackupAuthCredential_GetType: (credentialBytes: Uint8Array) => number;
  BackupAuthCredential_PresentDeterministic: (credentialBytes: Uint8Array, serverParamsBytes: Uint8Array, randomness: Uint8Array) => Uint8Array;
  BackupAuthCredentialPresentation_CheckValidContents: (presentationBytes: Uint8Array) => void;
  BackupAuthCredentialPresentation_Verify: (presentationBytes: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array) => void;
  BackupAuthCredentialPresentation_GetBackupId: (presentationBytes: Uint8Array) => Uint8Array;
  BackupAuthCredentialPresentation_GetBackupLevel: (presentationBytes: Uint8Array) => number;
  BackupAuthCredentialPresentation_GetType: (presentationBytes: Uint8Array) => number;
  GroupSendDerivedKeyPair_CheckValidContents: (bytes: Uint8Array) => void;
  GroupSendDerivedKeyPair_ForExpiration: (expiration: Timestamp, serverParams: Wrapper<ServerSecretParams>) => Uint8Array;
  GroupSendEndorsementsResponse_CheckValidContents: (bytes: Uint8Array) => void;
  GroupSendEndorsementsResponse_IssueDeterministic: (concatenatedGroupMemberCiphertexts: Uint8Array, keyPair: Uint8Array, randomness: Uint8Array) => Uint8Array;
  GroupSendEndorsementsResponse_GetExpiration: (responseBytes: Uint8Array) => Timestamp;
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds: (responseBytes: Uint8Array, groupMembers: Uint8Array, localUser: Uint8Array, now: Timestamp, groupParams: Serialized<GroupSecretParams>, serverParams: Wrapper<ServerPublicParams>) => Uint8Array[];
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts: (responseBytes: Uint8Array, concatenatedGroupMemberCiphertexts: Uint8Array, localUserCiphertext: Uint8Array, now: Timestamp, serverParams: Wrapper<ServerPublicParams>) => Uint8Array[];
  GroupSendEndorsement_CheckValidContents: (bytes: Uint8Array) => void;
  GroupSendEndorsement_Combine: (endorsements: Uint8Array[]) => Uint8Array;
  GroupSendEndorsement_Remove: (endorsement: Uint8Array, toRemove: Uint8Array) => Uint8Array;
  GroupSendEndorsement_ToToken: (endorsement: Uint8Array, groupParams: Serialized<GroupSecretParams>) => Uint8Array;
  GroupSendEndorsement_CallLinkParams_ToToken: (endorsement: Uint8Array, callLinkSecretParamsSerialized: Uint8Array) => Uint8Array;
  GroupSendToken_CheckValidContents: (bytes: Uint8Array) => void;
  GroupSendToken_ToFullToken: (token: Uint8Array, expiration: Timestamp) => Uint8Array;
  GroupSendFullToken_CheckValidContents: (bytes: Uint8Array) => void;
  GroupSendFullToken_GetExpiration: (token: Uint8Array) => Timestamp;
  GroupSendFullToken_Verify: (token: Uint8Array, userIds: Uint8Array, now: Timestamp, keyPair: Uint8Array) => void;
  LookupRequest_new: () => LookupRequest;
  LookupRequest_addE164: (request: Wrapper<LookupRequest>, e164: string) => void;
  LookupRequest_addPreviousE164: (request: Wrapper<LookupRequest>, e164: string) => void;
  LookupRequest_setToken: (request: Wrapper<LookupRequest>, token: Uint8Array) => void;
  LookupRequest_addAciAndAccessKey: (request: Wrapper<LookupRequest>, aci: Uint8Array, accessKey: Uint8Array) => void;
  CdsiLookup_new: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, request: Wrapper<LookupRequest>) => CancellablePromise<CdsiLookup>;
  CdsiLookup_token: (lookup: Wrapper<CdsiLookup>) => Uint8Array;
  CdsiLookup_complete: (asyncRuntime: Wrapper<TokioAsyncContext>, lookup: Wrapper<CdsiLookup>) => CancellablePromise<LookupResponse>;
  HttpRequest_new: (method: string, path: string, bodyAsSlice: Uint8Array | null) => HttpRequest;
  HttpRequest_add_header: (request: Wrapper<HttpRequest>, name: string, value: string) => void;
  ChatConnectionInfo_local_port: (connectionInfo: Wrapper<ChatConnectionInfo>) => number;
  ChatConnectionInfo_ip_version: (connectionInfo: Wrapper<ChatConnectionInfo>) => number;
  ChatConnectionInfo_description: (connectionInfo: Wrapper<ChatConnectionInfo>) => string;
  UnauthenticatedChatConnection_connect: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, languages: string[]) => CancellablePromise<UnauthenticatedChatConnection>;
  UnauthenticatedChatConnection_init_listener: (chat: Wrapper<UnauthenticatedChatConnection>, listener: ChatListener) => void;
  UnauthenticatedChatConnection_send: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number) => CancellablePromise<ChatResponse>;
  UnauthenticatedChatConnection_disconnect: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>) => CancellablePromise<void>;
  UnauthenticatedChatConnection_info: (chat: Wrapper<UnauthenticatedChatConnection>) => ChatConnectionInfo;
  UnauthenticatedChatConnection_look_up_username_hash: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, hash: Uint8Array) => CancellablePromise<Uuid | null>;
  UnauthenticatedChatConnection_look_up_username_link: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, uuid: Uuid, entropy: Uint8Array) => CancellablePromise<[string, Uint8Array] | null>;
  UnauthenticatedChatConnection_send_multi_recipient_message: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, payload: Uint8Array, timestamp: Timestamp, auth: Uint8Array|null, onlineOnly: boolean, isUrgent: boolean) => CancellablePromise<Uint8Array[]>;
  AuthenticatedChatConnection_preconnect: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>) => CancellablePromise<void>;
  AuthenticatedChatConnection_connect: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, receiveStories: boolean, languages: string[]) => CancellablePromise<AuthenticatedChatConnection>;
  AuthenticatedChatConnection_init_listener: (chat: Wrapper<AuthenticatedChatConnection>, listener: ChatListener) => void;
  AuthenticatedChatConnection_send: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number) => CancellablePromise<ChatResponse>;
  AuthenticatedChatConnection_disconnect: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>) => CancellablePromise<void>;
  AuthenticatedChatConnection_info: (chat: Wrapper<AuthenticatedChatConnection>) => ChatConnectionInfo;
  ServerMessageAck_SendStatus: (ack: Wrapper<ServerMessageAck>, status: number) => void;
  ProvisioningChatConnection_connect: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>) => CancellablePromise<ProvisioningChatConnection>;
  ProvisioningChatConnection_init_listener: (chat: Wrapper<ProvisioningChatConnection>, listener: ProvisioningListener) => void;
  ProvisioningChatConnection_info: (chat: Wrapper<ProvisioningChatConnection>) => ChatConnectionInfo;
  ProvisioningChatConnection_disconnect: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<ProvisioningChatConnection>) => CancellablePromise<void>;
  KeyTransparency_AciSearchKey: (aci: Uint8Array) => Uint8Array;
  KeyTransparency_E164SearchKey: (e164: string) => Uint8Array;
  KeyTransparency_UsernameHashSearchKey: (hash: Uint8Array) => Uint8Array;
  KeyTransparency_Search: (asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, aci: Uint8Array, aciIdentityKey: Wrapper<PublicKey>, e164: string | null, unidentifiedAccessKey: Uint8Array | null, usernameHash: Uint8Array | null, accountData: Uint8Array | null, lastDistinguishedTreeHead: Uint8Array) => CancellablePromise<Uint8Array>;
  KeyTransparency_Monitor: (asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, aci: Uint8Array, aciIdentityKey: Wrapper<PublicKey>, e164: string | null, unidentifiedAccessKey: Uint8Array | null, usernameHash: Uint8Array | null, accountData: Uint8Array | null, lastDistinguishedTreeHead: Uint8Array, isSelfMonitor: boolean) => CancellablePromise<Uint8Array>;
  KeyTransparency_Distinguished: (asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, lastDistinguishedTreeHead: Uint8Array | null) => CancellablePromise<Uint8Array>;
  UnauthenticatedChatConnection_account_exists: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, account: Uint8Array) => CancellablePromise<boolean>;
  RegistrationService_CreateSession: (asyncRuntime: Wrapper<TokioAsyncContext>, createSession: RegistrationCreateSessionRequest, connectChat: ConnectChatBridge) => CancellablePromise<RegistrationService>;
  RegistrationService_ResumeSession: (asyncRuntime: Wrapper<TokioAsyncContext>, sessionId: string, number: string, connectChat: ConnectChatBridge) => CancellablePromise<RegistrationService>;
  RegistrationService_RequestVerificationCode: (asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, transport: string, client: string, languages: string[]) => CancellablePromise<void>;
  RegistrationService_SubmitVerificationCode: (asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, code: string) => CancellablePromise<void>;
  RegistrationService_SubmitCaptcha: (asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, captchaValue: string) => CancellablePromise<void>;
  RegistrationService_CheckSvr2Credentials: (asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, svrTokens: string[]) => CancellablePromise<CheckSvr2CredentialsResponse>;
  RegistrationService_RegisterAccount: (asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, registerAccount: Wrapper<RegisterAccountRequest>, accountAttributes: Wrapper<RegistrationAccountAttributes>) => CancellablePromise<RegisterAccountResponse>;
  RegistrationService_ReregisterAccount: (asyncRuntime: Wrapper<TokioAsyncContext>, connectChat: ConnectChatBridge, number: string, registerAccount: Wrapper<RegisterAccountRequest>, accountAttributes: Wrapper<RegistrationAccountAttributes>) => CancellablePromise<RegisterAccountResponse>;
  RegistrationService_SessionId: (service: Wrapper<RegistrationService>) => string;
  RegistrationService_RegistrationSession: (service: Wrapper<RegistrationService>) => RegistrationSession;
  RegistrationSession_GetAllowedToRequestCode: (session: Wrapper<RegistrationSession>) => boolean;
  RegistrationSession_GetVerified: (session: Wrapper<RegistrationSession>) => boolean;
  RegistrationSession_GetNextCallSeconds: (session: Wrapper<RegistrationSession>) => number | null;
  RegistrationSession_GetNextSmsSeconds: (session: Wrapper<RegistrationSession>) => number | null;
  RegistrationSession_GetNextVerificationAttemptSeconds: (session: Wrapper<RegistrationSession>) => number | null;
  RegistrationSession_GetRequestedInformation: (session: Wrapper<RegistrationSession>) => ChallengeOption[];
  RegisterAccountRequest_Create: () => RegisterAccountRequest;
  RegisterAccountRequest_SetSkipDeviceTransfer: (registerAccount: Wrapper<RegisterAccountRequest>) => void;
  RegisterAccountRequest_SetAccountPassword: (registerAccount: Wrapper<RegisterAccountRequest>, accountPassword: string) => void;
  RegisterAccountRequest_SetIdentityPublicKey: (registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, identityKey: Wrapper<PublicKey>) => void;
  RegisterAccountRequest_SetIdentitySignedPreKey: (registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, signedPreKey: SignedPublicPreKey) => void;
  RegisterAccountRequest_SetIdentityPqLastResortPreKey: (registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, pqLastResortPreKey: SignedPublicPreKey) => void;
  RegistrationAccountAttributes_Create: (recoveryPassword: Uint8Array, aciRegistrationId: number, pniRegistrationId: number, registrationLock: string | null, unidentifiedAccessKey: Uint8Array, unrestrictedUnidentifiedAccess: boolean, capabilities: string[], discoverableByPhoneNumber: boolean) => RegistrationAccountAttributes;
  RegisterAccountResponse_GetIdentity: (response: Wrapper<RegisterAccountResponse>, identityType: number) => Uint8Array;
  RegisterAccountResponse_GetNumber: (response: Wrapper<RegisterAccountResponse>) => string;
  RegisterAccountResponse_GetUsernameHash: (response: Wrapper<RegisterAccountResponse>) => Uint8Array | null;
  RegisterAccountResponse_GetUsernameLinkHandle: (response: Wrapper<RegisterAccountResponse>) => Uuid | null;
  RegisterAccountResponse_GetStorageCapable: (response: Wrapper<RegisterAccountResponse>) => boolean;
  RegisterAccountResponse_GetReregistration: (response: Wrapper<RegisterAccountResponse>) => boolean;
  RegisterAccountResponse_GetEntitlementBadges: (response: Wrapper<RegisterAccountResponse>) => RegisterResponseBadge[];
  RegisterAccountResponse_GetEntitlementBackupLevel: (response: Wrapper<RegisterAccountResponse>) => bigint | null;
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds: (response: Wrapper<RegisterAccountResponse>) => bigint | null;
  SecureValueRecoveryForBackups_CreateNewBackupChain: (environment: number, backupKey: Uint8Array) => Uint8Array;
  SecureValueRecoveryForBackups_StoreBackup: (asyncRuntime: Wrapper<TokioAsyncContext>, backupKey: Uint8Array, previousSecretData: Uint8Array, connectionManager: Wrapper<ConnectionManager>, username: string, password: string) => CancellablePromise<BackupStoreResponse>;
  SecureValueRecoveryForBackups_RestoreBackupFromServer: (asyncRuntime: Wrapper<TokioAsyncContext>, backupKey: Uint8Array, metadata: Uint8Array, connectionManager: Wrapper<ConnectionManager>, username: string, password: string) => CancellablePromise<BackupRestoreResponse>;
  SecureValueRecoveryForBackups_RemoveBackup: (asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string) => CancellablePromise<void>;
  BackupStoreResponse_GetForwardSecrecyToken: (response: Wrapper<BackupStoreResponse>) => Uint8Array;
  BackupStoreResponse_GetOpaqueMetadata: (response: Wrapper<BackupStoreResponse>) => Uint8Array;
  BackupStoreResponse_GetNextBackupSecretData: (response: Wrapper<BackupStoreResponse>) => Uint8Array;
  BackupRestoreResponse_GetForwardSecrecyToken: (response: Wrapper<BackupRestoreResponse>) => Uint8Array;
  BackupRestoreResponse_GetNextBackupSecretData: (response: Wrapper<BackupRestoreResponse>) => Uint8Array;
  TokioAsyncContext_new: () => TokioAsyncContext;
  TokioAsyncContext_cancel: (context: Wrapper<TokioAsyncContext>, rawCancellationId: bigint) => void;
  ConnectionProxyConfig_new: (scheme: string, host: string, port: number, username: string | null, password: string | null) => ConnectionProxyConfig;
  ConnectionManager_new: (environment: number, userAgent: string, remoteConfig: Wrapper<BridgedStringMap>, buildVariant: number) => ConnectionManager;
  ConnectionManager_set_proxy: (connectionManager: Wrapper<ConnectionManager>, proxy: Wrapper<ConnectionProxyConfig>) => void;
  ConnectionManager_set_invalid_proxy: (connectionManager: Wrapper<ConnectionManager>) => void;
  ConnectionManager_clear_proxy: (connectionManager: Wrapper<ConnectionManager>) => void;
  ConnectionManager_set_ipv6_enabled: (connectionManager: Wrapper<ConnectionManager>, ipv6Enabled: boolean) => void;
  ConnectionManager_set_censorship_circumvention_enabled: (connectionManager: Wrapper<ConnectionManager>, enabled: boolean) => void;
  ConnectionManager_set_remote_config: (connectionManager: Wrapper<ConnectionManager>, remoteConfig: Wrapper<BridgedStringMap>, buildVariant: number) => void;
  ConnectionManager_on_network_change: (connectionManager: Wrapper<ConnectionManager>) => void;
  AccountEntropyPool_Generate: () => string;
  AccountEntropyPool_IsValid: (accountEntropy: string) => boolean;
  AccountEntropyPool_DeriveSvrKey: (accountEntropy: AccountEntropyPool) => Uint8Array;
  AccountEntropyPool_DeriveBackupKey: (accountEntropy: AccountEntropyPool) => Uint8Array;
  BackupKey_DeriveBackupId: (backupKey: Uint8Array, aci: Uint8Array) => Uint8Array;
  BackupKey_DeriveEcKey: (backupKey: Uint8Array, aci: Uint8Array) => PrivateKey;
  BackupKey_DeriveLocalBackupMetadataKey: (backupKey: Uint8Array) => Uint8Array;
  BackupKey_DeriveMediaId: (backupKey: Uint8Array, mediaName: string) => Uint8Array;
  BackupKey_DeriveMediaEncryptionKey: (backupKey: Uint8Array, mediaId: Uint8Array) => Uint8Array;
  BackupKey_DeriveThumbnailTransitEncryptionKey: (backupKey: Uint8Array, mediaId: Uint8Array) => Uint8Array;
  IncrementalMac_CalculateChunkSize: (dataSize: number) => number;
  IncrementalMac_Initialize: (key: Uint8Array, chunkSize: number) => IncrementalMac;
  IncrementalMac_Update: (mac: Wrapper<IncrementalMac>, bytes: Uint8Array, offset: number, length: number) => Uint8Array;
  IncrementalMac_Finalize: (mac: Wrapper<IncrementalMac>) => Uint8Array;
  ValidatingMac_Initialize: (key: Uint8Array, chunkSize: number, digests: Uint8Array) => ValidatingMac | null;
  ValidatingMac_Update: (mac: Wrapper<ValidatingMac>, bytes: Uint8Array, offset: number, length: number) => number;
  ValidatingMac_Finalize: (mac: Wrapper<ValidatingMac>) => number;
  MessageBackupKey_FromAccountEntropyPool: (accountEntropy: AccountEntropyPool, aci: Uint8Array, forwardSecrecyToken: Uint8Array | null) => MessageBackupKey;
  MessageBackupKey_FromBackupKeyAndBackupId: (backupKey: Uint8Array, backupId: Uint8Array, forwardSecrecyToken: Uint8Array | null) => MessageBackupKey;
  MessageBackupKey_GetHmacKey: (key: Wrapper<MessageBackupKey>) => Uint8Array;
  MessageBackupKey_GetAesKey: (key: Wrapper<MessageBackupKey>) => Uint8Array;
  MessageBackupValidator_Validate: (key: Wrapper<MessageBackupKey>, firstStream: InputStream, secondStream: InputStream, len: bigint, purpose: number) => Promise<MessageBackupValidationOutcome>;
  OnlineBackupValidator_New: (backupInfoFrame: Uint8Array, purpose: number) => OnlineBackupValidator;
  OnlineBackupValidator_AddFrame: (backup: Wrapper<OnlineBackupValidator>, frame: Uint8Array) => void;
  OnlineBackupValidator_Finalize: (backup: Wrapper<OnlineBackupValidator>) => void;
  BackupJsonExporter_New: (backupInfo: Uint8Array, shouldValidate: boolean) => BackupJsonExporter;
  BackupJsonExporter_GetInitialChunk: (exporter: Wrapper<BackupJsonExporter>) => string;
  BackupJsonExporter_ExportFrames: (exporter: Wrapper<BackupJsonExporter>, frames: Uint8Array) => JsonFrameExportResult[];
  BackupJsonExporter_Finish: (exporter: Wrapper<BackupJsonExporter>) => void;
  Username_Hash: (username: string) => Uint8Array;
  Username_Proof: (username: string, randomness: Uint8Array) => Uint8Array;
  Username_Verify: (proof: Uint8Array, hash: Uint8Array) => void;
  Username_CandidatesFrom: (nickname: string, minLen: number, maxLen: number) => string[];
  Username_HashFromParts: (nickname: string, discriminator: string, minLen: number, maxLen: number) => Uint8Array;
  UsernameLink_Create: (username: string, entropy: Uint8Array | null) => Uint8Array;
  UsernameLink_DecryptUsername: (entropy: Uint8Array, encryptedUsername: Uint8Array) => string;
  SignalMedia_CheckAvailable: () => void;
  Mp4Sanitizer_Sanitize: (input: InputStream, len: bigint) => Promise<SanitizedMetadata>;
  WebpSanitizer_Sanitize: (input: SyncInputStream) => void;
  SanitizedMetadata_GetMetadata: (sanitized: Wrapper<SanitizedMetadata>) => Uint8Array;
  SanitizedMetadata_GetDataOffset: (sanitized: Wrapper<SanitizedMetadata>) => bigint;
  SanitizedMetadata_GetDataLen: (sanitized: Wrapper<SanitizedMetadata>) => bigint;
  BridgedStringMap_new: (initialCapacity: number) => BridgedStringMap;
  BridgedStringMap_insert: (map: Wrapper<BridgedStringMap>, key: string, value: string) => void;
  TESTING_NonSuspendingBackgroundThreadRuntime_New: () => NonSuspendingBackgroundThreadRuntime;
  TESTING_FutureSuccess: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number) => CancellablePromise<number>;
  TESTING_TokioAsyncContext_FutureSuccessBytes: (asyncRuntime: Wrapper<TokioAsyncContext>, count: number) => CancellablePromise<Uint8Array>;
  TESTING_FutureFailure: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: number) => CancellablePromise<number>;
  TESTING_FutureCancellationCounter_Create: (initialValue: number) => TestingFutureCancellationCounter;
  TESTING_FutureCancellationCounter_WaitForCount: (asyncRuntime: Wrapper<TokioAsyncContext>, count: Wrapper<TestingFutureCancellationCounter>, target: number) => CancellablePromise<void>;
  TESTING_FutureIncrementOnCancel: (asyncRuntime: Wrapper<TokioAsyncContext>, _guard: TestingFutureCancellationGuard) => CancellablePromise<void>;
  TESTING_TokioAsyncFuture: (asyncRuntime: Wrapper<TokioAsyncContext>, input: number) => CancellablePromise<number>;
  TESTING_TestingHandleType_getValue: (handle: Wrapper<TestingHandleType>) => number;
  TESTING_FutureProducesPointerType: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number) => CancellablePromise<TestingHandleType>;
  TESTING_OtherTestingHandleType_getValue: (handle: Wrapper<OtherTestingHandleType>) => string;
  TESTING_FutureProducesOtherPointerType: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: string) => CancellablePromise<OtherTestingHandleType>;
  TESTING_PanicOnBorrowSync: (_input: null) => void;
  TESTING_PanicOnBorrowAsync: (_input: null) => Promise<void>;
  TESTING_PanicOnBorrowIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null) => CancellablePromise<void>;
  TESTING_ErrorOnBorrowSync: (_input: null) => void;
  TESTING_ErrorOnBorrowAsync: (_input: null) => Promise<void>;
  TESTING_ErrorOnBorrowIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null) => CancellablePromise<void>;
  TESTING_PanicOnLoadSync: (_needsCleanup: null, _input: null) => void;
  TESTING_PanicOnLoadAsync: (_needsCleanup: null, _input: null) => Promise<void>;
  TESTING_PanicOnLoadIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null, _input: null) => CancellablePromise<void>;
  TESTING_PanicInBodySync: (_input: null) => void;
  TESTING_PanicInBodyAsync: (_input: null) => Promise<void>;
  TESTING_PanicInBodyIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null) => CancellablePromise<void>;
  TESTING_PanicOnReturnSync: (_needsCleanup: null) => null;
  TESTING_PanicOnReturnAsync: (_needsCleanup: null) => Promise<null>;
  TESTING_PanicOnReturnIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null) => CancellablePromise<null>;
  TESTING_ErrorOnReturnSync: (_needsCleanup: null) => null;
  TESTING_ErrorOnReturnAsync: (_needsCleanup: null) => Promise<null>;
  TESTING_ErrorOnReturnIo: (asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null) => CancellablePromise<null>;
  TESTING_ReturnStringArray: () => string[];
  TESTING_JoinStringArray: (array: string[], joinWith: string) => string;
  TESTING_ProcessBytestringArray: (input: Uint8Array[]) => Uint8Array[];
  TESTING_RoundTripU8: (input: number) => number;
  TESTING_RoundTripU16: (input: number) => number;
  TESTING_RoundTripU32: (input: number) => number;
  TESTING_RoundTripI32: (input: number) => number;
  TESTING_RoundTripU64: (input: bigint) => bigint;
  TESTING_ConvertOptionalUuid: (present: boolean) => Uuid | null;
  TESTING_InputStreamReadIntoZeroLengthSlice: (capsAlphabetInput: InputStream) => Promise<Uint8Array>;
  ComparableBackup_ReadUnencrypted: (stream: InputStream, len: bigint, purpose: number) => Promise<ComparableBackup>;
  ComparableBackup_GetComparableString: (backup: Wrapper<ComparableBackup>) => string;
  ComparableBackup_GetUnknownFields: (backup: Wrapper<ComparableBackup>) => string[];
  TESTING_FakeChatServer_Create: () => FakeChatServer;
  TESTING_FakeChatServer_GetNextRemote: (asyncRuntime: Wrapper<TokioAsyncContext>, server: Wrapper<FakeChatServer>) => CancellablePromise<FakeChatRemoteEnd>;
  TESTING_FakeChatConnection_Create: (tokio: Wrapper<TokioAsyncContext>, listener: ChatListener, alertsJoinedByNewlines: string) => FakeChatConnection;
  TESTING_FakeChatConnection_CreateProvisioning: (tokio: Wrapper<TokioAsyncContext>, listener: ProvisioningListener) => FakeChatConnection;
  TESTING_FakeChatConnection_TakeAuthenticatedChat: (chat: Wrapper<FakeChatConnection>) => AuthenticatedChatConnection;
  TESTING_FakeChatConnection_TakeUnauthenticatedChat: (chat: Wrapper<FakeChatConnection>) => UnauthenticatedChatConnection;
  TESTING_FakeChatConnection_TakeProvisioningChat: (chat: Wrapper<FakeChatConnection>) => ProvisioningChatConnection;
  TESTING_FakeChatConnection_TakeRemote: (chat: Wrapper<FakeChatConnection>) => FakeChatRemoteEnd;
  TESTING_FakeChatRemoteEnd_SendRawServerRequest: (chat: Wrapper<FakeChatRemoteEnd>, bytes: Uint8Array) => void;
  TESTING_FakeChatRemoteEnd_SendRawServerResponse: (chat: Wrapper<FakeChatRemoteEnd>, bytes: Uint8Array) => void;
  TESTING_FakeChatRemoteEnd_SendServerResponse: (chat: Wrapper<FakeChatRemoteEnd>, response: Wrapper<FakeChatResponse>) => void;
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted: (chat: Wrapper<FakeChatRemoteEnd>) => void;
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest: (asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<FakeChatRemoteEnd>) => CancellablePromise<[HttpRequest, bigint] | null>;
  TESTING_ChatResponseConvert: (bodyPresent: boolean) => ChatResponse;
  TESTING_ChatRequestGetMethod: (request: Wrapper<HttpRequest>) => string;
  TESTING_ChatRequestGetPath: (request: Wrapper<HttpRequest>) => string;
  TESTING_ChatRequestGetHeaderNames: (request: Wrapper<HttpRequest>) => string[];
  TESTING_ChatRequestGetHeaderValue: (request: Wrapper<HttpRequest>, headerName: string) => string;
  TESTING_ChatRequestGetBody: (request: Wrapper<HttpRequest>) => Uint8Array;
  TESTING_FakeChatResponse_Create: (id: bigint, status: number, message: string, headers: string[], body: Uint8Array | null) => FakeChatResponse;
  TESTING_ChatConnectErrorConvert: (errorDescription: string) => void;
  TESTING_ChatSendErrorConvert: (errorDescription: string) => void;
  TESTING_KeyTransFatalVerificationFailure: () => void;
  TESTING_KeyTransNonFatalVerificationFailure: () => void;
  TESTING_KeyTransChatSendError: () => void;
  TESTING_RegistrationSessionInfoConvert: () => RegistrationSession;
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert: () => CheckSvr2CredentialsResponse;
  TESTING_FakeRegistrationSession_CreateSession: (asyncRuntime: Wrapper<TokioAsyncContext>, createSession: RegistrationCreateSessionRequest, chat: Wrapper<FakeChatServer>) => CancellablePromise<RegistrationService>;
  TESTING_RegisterAccountResponse_CreateTestValue: () => RegisterAccountResponse;
  TESTING_RegistrationService_CreateSessionErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_ResumeSessionErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_UpdateSessionErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_SubmitVerificationErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert: (errorDescription: string) => void;
  TESTING_RegistrationService_RegisterAccountErrorConvert: (errorDescription: string) => void;
  TESTING_CdsiLookupResponseConvert: (asyncRuntime: Wrapper<TokioAsyncContext>) => CancellablePromise<LookupResponse>;
  TESTING_CdsiLookupErrorConvert: (errorDescription: string) => void;
  TESTING_ServerMessageAck_Create: () => ServerMessageAck;
  TESTING_ConnectionManager_newLocalOverride: (userAgent: string, chatPort: number, cdsiPort: number, svr2Port: number, svrBPort: number, rootCertificateDer: Uint8Array) => ConnectionManager;
  TESTING_ConnectionManager_isUsingProxy: (manager: Wrapper<ConnectionManager>) => number;
  TESTING_CreateOTP: (username: string, secret: Uint8Array) => string;
  TESTING_CreateOTPFromBase64: (username: string, secret: string) => string;
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly: (sourcePublicKey: Wrapper<PublicKey>, signedPreKey: SignedPublicPreKey) => void;
  TestingSemaphore_New: (initial: number) => TestingSemaphore;
  TestingSemaphore_AddPermits: (semaphore: Wrapper<TestingSemaphore>, permits: number) => void;
  TestingValueHolder_New: (value: number) => TestingValueHolder;
  TestingValueHolder_Get: (holder: Wrapper<TestingValueHolder>) => number;
  TESTING_ReturnPair: () => [number, string];
  test_only_fn_returns_123: () => number;
  TESTING_BridgedStringMap_dump_to_json: (map: Wrapper<BridgedStringMap>) => string;
  TESTING_TokioAsyncContext_NewSingleThreaded: () => TokioAsyncContext;

  // FFI-only functions (not available in Node.js bridge)
  Hkdf_Derive: (output: Uint8Array, ikm: Uint8Array, label: Uint8Array, salt: Uint8Array) => void;
  Aes256_Ctr32_New: (key: Uint8Array, nonce: Uint8Array, initialCtr: number) => Aes256Ctr32;
  Aes256_Ctr32_Process: (obj: Wrapper<Aes256Ctr32>, data: Uint8Array) => Uint8Array;
  Aes256_Gcm_Encryption_New: (key: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array) => Aes256GcmEncryption;
  Aes256_Gcm_Encryption_Update: (obj: Wrapper<Aes256GcmEncryption>, data: Uint8Array) => Uint8Array;
  Aes256_Gcm_Encryption_Compute_Tag: (obj: Wrapper<Aes256GcmEncryption>) => Uint8Array;
  Aes256_Gcm_Decryption_New: (key: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array) => Aes256GcmDecryption;
  Aes256_Gcm_Decryption_Update: (obj: Wrapper<Aes256GcmDecryption>, data: Uint8Array) => Uint8Array;
  Aes256_Gcm_Decryption_Verify_Tag: (obj: Wrapper<Aes256GcmDecryption>, tag: Uint8Array) => boolean;
  Hex_Encode: (data: Uint8Array) => string;
  Pin_Hash_From_Salt: (pin: Uint8Array, salt: Uint8Array) => PinHash;
  Pin_Hash_From_Username_Mrenclave: (pin: Uint8Array, username: string, mrenclave: Uint8Array) => PinHash;
  Pin_Hash_Access_Key: (hash: Wrapper<PinHash>) => Uint8Array;
  Pin_Hash_Encryption_Key: (hash: Wrapper<PinHash>) => Uint8Array;
  Pin_Local_Hash: (pin: Uint8Array) => string;
  Pin_Verify_Local_Hash: (encodedHash: string, pin: Uint8Array) => boolean;
  Svr2_Client_New: (mrenclave: Uint8Array, attestationMsg: Uint8Array, currentDate: number, env: number) => Sgx2Client;
  Message_Get_Sender_Ratchet_Key: (msg: Wrapper<SignalMessage>) => PublicKey;
  Pre_Key_Signal_Message_Get_Base_Key: (msg: Wrapper<PreKeySignalMessage>) => PublicKey;
  Pre_Key_Signal_Message_Get_Identity_Key: (msg: Wrapper<PreKeySignalMessage>) => PublicKey;
  Pre_Key_Signal_Message_Get_Signal_Message: (msg: Wrapper<PreKeySignalMessage>) => Uint8Array;
  Sender_Key_Distribution_Message_Get_Signature_Key: (msg: Wrapper<SenderKeyDistributionMessage>) => PublicKey;
  Unidentified_Sender_Message_Content_Get_Group_Id_Or_Empty: (msg: Wrapper<UnidentifiedSenderMessageContent>) => Uint8Array;
  Device_Transfer_Generate_Private_Key: () => Uint8Array;
  Device_Transfer_Generate_Private_Key_With_Format: (keyFormat: number) => Uint8Array;
  Device_Transfer_Generate_Certificate: (privateKey: Uint8Array, name: string, daysToExpire: number) => Uint8Array;
  Http_Request_New_With_Body: (method: string, url: string, contentType: string, body: Uint8Array) => HttpRequest;
  Http_Request_New_Without_Body: (method: string, url: string) => HttpRequest;
  Server_Message_Ack_Send: (ack: Wrapper<ServerMessageAck>, status: number) => void;
  Message_Backup_Validation_Outcome_Get_Error_Message: (outcome: Wrapper<MessageBackupValidationOutcome>) => string | null;
  Message_Backup_Validation_Outcome_Get_Unknown_Fields: (outcome: Wrapper<MessageBackupValidationOutcome>) => string[];
  Register_Account_Request_Set_Apn_Push_Token: (req: Wrapper<RegisterAccountRequest>, token: string) => void;
  Registration_Service_Request_Push_Challenge: (svc: Wrapper<RegistrationService>) => void;
  Registration_Service_Submit_Push_Challenge: (svc: Wrapper<RegistrationService>, challenge: string) => void;
  Unidentified_Sender_Message_Content_New_From_Content_And_Type: (content: Uint8Array, contentType: number) => UnidentifiedSenderMessageContent;
  UsernameLink_CreateAllowingEmptyEntropy: (username: string, entropy: Uint8Array) => Uint8Array;
};

const native = getNativeModule();

const { registerErrors, 
  initLogger,
  SealedSenderMultiRecipientMessage_Parse,
  MinidumpToJSONString,
  Aes256GcmSiv_New,
  Aes256GcmSiv_Encrypt,
  Aes256GcmSiv_Decrypt,
  PublicKey_HpkeSeal,
  PrivateKey_HpkeOpen,
  HKDF_DeriveSecrets,
  ServiceId_ServiceIdBinary,
  ServiceId_ServiceIdString,
  ServiceId_ServiceIdLog,
  ServiceId_ParseFromServiceIdBinary,
  ServiceId_ParseFromServiceIdString,
  ProtocolAddress_New,
  PublicKey_Deserialize,
  PublicKey_Serialize,
  PublicKey_GetPublicKeyBytes,
  ProtocolAddress_DeviceId,
  ProtocolAddress_Name,
  PublicKey_Equals,
  PublicKey_Verify,
  PrivateKey_Deserialize,
  PrivateKey_Serialize,
  PrivateKey_Generate,
  PrivateKey_GetPublicKey,
  PrivateKey_Sign,
  PrivateKey_Agree,
  KyberPublicKey_Serialize,
  KyberPublicKey_Deserialize,
  KyberSecretKey_Serialize,
  KyberSecretKey_Deserialize,
  KyberPublicKey_Equals,
  KyberKeyPair_Generate,
  KyberKeyPair_GetPublicKey,
  KyberKeyPair_GetSecretKey,
  IdentityKeyPair_Serialize,
  IdentityKeyPair_Deserialize,
  IdentityKeyPair_SignAlternateIdentity,
  IdentityKey_VerifyAlternateIdentity,
  Fingerprint_New,
  Fingerprint_ScannableEncoding,
  Fingerprint_DisplayString,
  ScannableFingerprint_Compare,
  SignalMessage_Deserialize,
  SignalMessage_GetBody,
  SignalMessage_GetSerialized,
  SignalMessage_GetCounter,
  SignalMessage_GetMessageVersion,
  SignalMessage_GetPqRatchet,
  SignalMessage_New,
  SignalMessage_VerifyMac,
  PreKeySignalMessage_New,
  PreKeySignalMessage_Deserialize,
  PreKeySignalMessage_Serialize,
  PreKeySignalMessage_GetRegistrationId,
  PreKeySignalMessage_GetSignedPreKeyId,
  PreKeySignalMessage_GetPreKeyId,
  PreKeySignalMessage_GetVersion,
  SenderKeyMessage_Deserialize,
  SenderKeyMessage_GetCipherText,
  SenderKeyMessage_Serialize,
  SenderKeyMessage_GetDistributionId,
  SenderKeyMessage_GetChainId,
  SenderKeyMessage_GetIteration,
  SenderKeyMessage_New,
  SenderKeyMessage_VerifySignature,
  SenderKeyDistributionMessage_Deserialize,
  SenderKeyDistributionMessage_GetChainKey,
  SenderKeyDistributionMessage_Serialize,
  SenderKeyDistributionMessage_GetDistributionId,
  SenderKeyDistributionMessage_GetChainId,
  SenderKeyDistributionMessage_GetIteration,
  SenderKeyDistributionMessage_New,
  DecryptionErrorMessage_Deserialize,
  DecryptionErrorMessage_GetTimestamp,
  DecryptionErrorMessage_GetDeviceId,
  DecryptionErrorMessage_Serialize,
  DecryptionErrorMessage_GetRatchetKey,
  DecryptionErrorMessage_ForOriginalMessage,
  DecryptionErrorMessage_ExtractFromSerializedContent,
  PlaintextContent_Deserialize,
  PlaintextContent_Serialize,
  PlaintextContent_GetBody,
  PlaintextContent_FromDecryptionErrorMessage,
  PreKeyBundle_New,
  PreKeyBundle_GetIdentityKey,
  PreKeyBundle_GetSignedPreKeySignature,
  PreKeyBundle_GetKyberPreKeySignature,
  PreKeyBundle_GetRegistrationId,
  PreKeyBundle_GetDeviceId,
  PreKeyBundle_GetSignedPreKeyId,
  PreKeyBundle_GetKyberPreKeyId,
  PreKeyBundle_GetPreKeyId,
  PreKeyBundle_GetPreKeyPublic,
  PreKeyBundle_GetSignedPreKeyPublic,
  PreKeyBundle_GetKyberPreKeyPublic,
  SignedPreKeyRecord_Deserialize,
  SignedPreKeyRecord_GetSignature,
  SignedPreKeyRecord_Serialize,
  SignedPreKeyRecord_GetId,
  SignedPreKeyRecord_GetTimestamp,
  SignedPreKeyRecord_GetPublicKey,
  SignedPreKeyRecord_GetPrivateKey,
  KyberPreKeyRecord_Deserialize,
  KyberPreKeyRecord_GetSignature,
  KyberPreKeyRecord_Serialize,
  KyberPreKeyRecord_GetId,
  KyberPreKeyRecord_GetTimestamp,
  KyberPreKeyRecord_GetPublicKey,
  KyberPreKeyRecord_GetSecretKey,
  KyberPreKeyRecord_GetKeyPair,
  SignedPreKeyRecord_New,
  KyberPreKeyRecord_New,
  PreKeyRecord_Deserialize,
  PreKeyRecord_Serialize,
  PreKeyRecord_GetId,
  PreKeyRecord_GetPublicKey,
  PreKeyRecord_GetPrivateKey,
  PreKeyRecord_New,
  SenderKeyRecord_Deserialize,
  SenderKeyRecord_Serialize,
  ServerCertificate_Deserialize,
  ServerCertificate_GetSerialized,
  ServerCertificate_GetCertificate,
  ServerCertificate_GetSignature,
  ServerCertificate_GetKeyId,
  ServerCertificate_GetKey,
  ServerCertificate_New,
  SenderCertificate_Deserialize,
  SenderCertificate_GetSerialized,
  SenderCertificate_GetCertificate,
  SenderCertificate_GetSignature,
  SenderCertificate_GetSenderUuid,
  SenderCertificate_GetSenderE164,
  SenderCertificate_GetExpiration,
  SenderCertificate_GetDeviceId,
  SenderCertificate_GetKey,
  SenderCertificate_Validate,
  SenderCertificate_GetServerCertificate,
  SenderCertificate_New,
  UnidentifiedSenderMessageContent_Deserialize,
  UnidentifiedSenderMessageContent_Serialize,
  UnidentifiedSenderMessageContent_GetContents,
  UnidentifiedSenderMessageContent_GetGroupId,
  UnidentifiedSenderMessageContent_GetSenderCert,
  UnidentifiedSenderMessageContent_GetMsgType,
  UnidentifiedSenderMessageContent_GetContentHint,
  UnidentifiedSenderMessageContent_New,
  CiphertextMessage_Type,
  CiphertextMessage_Serialize,
  CiphertextMessage_FromPlaintextContent,
  SessionRecord_ArchiveCurrentState,
  SessionRecord_HasUsableSenderChain,
  SessionRecord_CurrentRatchetKeyMatches,
  SessionRecord_Deserialize,
  SessionRecord_Serialize,
  SessionRecord_GetLocalRegistrationId,
  SessionRecord_GetRemoteRegistrationId,
  SealedSenderDecryptionResult_GetSenderUuid,
  SealedSenderDecryptionResult_GetSenderE164,
  SealedSenderDecryptionResult_GetDeviceId,
  SealedSenderDecryptionResult_Message,
  SessionBuilder_ProcessPreKeyBundle,
  SessionCipher_EncryptMessage,
  SessionCipher_DecryptSignalMessage,
  SessionCipher_DecryptPreKeySignalMessage,
  SealedSender_Encrypt,
  SealedSender_MultiRecipientEncrypt,
  SealedSender_MultiRecipientMessageForSingleRecipient,
  SealedSender_DecryptToUsmc,
  SealedSender_DecryptMessage,
  SenderKeyDistributionMessage_Create,
  SenderKeyDistributionMessage_Process,
  GroupCipher_EncryptMessage,
  GroupCipher_DecryptMessage,
  Cds2ClientState_New,
  HsmEnclaveClient_New,
  HsmEnclaveClient_CompleteHandshake,
  HsmEnclaveClient_EstablishedSend,
  HsmEnclaveClient_EstablishedRecv,
  HsmEnclaveClient_InitialRequest,
  SgxClientState_InitialRequest,
  SgxClientState_CompleteHandshake,
  SgxClientState_EstablishedSend,
  SgxClientState_EstablishedRecv,
  ExpiringProfileKeyCredential_CheckValidContents,
  ExpiringProfileKeyCredentialResponse_CheckValidContents,
  GroupMasterKey_CheckValidContents,
  GroupPublicParams_CheckValidContents,
  GroupSecretParams_CheckValidContents,
  ProfileKey_CheckValidContents,
  ProfileKeyCiphertext_CheckValidContents,
  ProfileKeyCommitment_CheckValidContents,
  ProfileKeyCredentialRequest_CheckValidContents,
  ProfileKeyCredentialRequestContext_CheckValidContents,
  ReceiptCredential_CheckValidContents,
  ReceiptCredentialPresentation_CheckValidContents,
  ReceiptCredentialRequest_CheckValidContents,
  ReceiptCredentialRequestContext_CheckValidContents,
  ReceiptCredentialResponse_CheckValidContents,
  UuidCiphertext_CheckValidContents,
  ServerPublicParams_Deserialize,
  ServerPublicParams_Serialize,
  ServerSecretParams_Deserialize,
  ServerSecretParams_Serialize,
  ProfileKey_GetCommitment,
  ProfileKey_GetProfileKeyVersion,
  ProfileKey_DeriveAccessKey,
  GroupSecretParams_GenerateDeterministic,
  GroupSecretParams_DeriveFromMasterKey,
  GroupSecretParams_GetMasterKey,
  GroupSecretParams_GetPublicParams,
  GroupSecretParams_EncryptServiceId,
  GroupSecretParams_DecryptServiceId,
  GroupSecretParams_EncryptProfileKey,
  GroupSecretParams_DecryptProfileKey,
  GroupSecretParams_EncryptBlobWithPaddingDeterministic,
  GroupSecretParams_DecryptBlobWithPadding,
  ServerSecretParams_GenerateDeterministic,
  ServerSecretParams_GetPublicParams,
  ServerSecretParams_SignDeterministic,
  ServerPublicParams_GetEndorsementPublicKey,
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId,
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic,
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic,
  ServerPublicParams_ReceiveExpiringProfileKeyCredential,
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic,
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic,
  ServerPublicParams_ReceiveReceiptCredential,
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic,
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic,
  AuthCredentialWithPni_CheckValidContents,
  AuthCredentialWithPniResponse_CheckValidContents,
  ServerSecretParams_VerifyAuthCredentialPresentation,
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic,
  ServerSecretParams_VerifyProfileKeyCredentialPresentation,
  ServerSecretParams_IssueReceiptCredentialDeterministic,
  ServerSecretParams_VerifyReceiptCredentialPresentation,
  GroupPublicParams_GetGroupIdentifier,
  ServerPublicParams_VerifySignature,
  AuthCredentialPresentation_CheckValidContents,
  AuthCredentialPresentation_GetUuidCiphertext,
  AuthCredentialPresentation_GetPniCiphertext,
  AuthCredentialPresentation_GetRedemptionTime,
  ProfileKeyCredentialRequestContext_GetRequest,
  ExpiringProfileKeyCredential_GetExpirationTime,
  ProfileKeyCredentialPresentation_CheckValidContents,
  ProfileKeyCredentialPresentation_GetUuidCiphertext,
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext,
  ReceiptCredentialRequestContext_GetRequest,
  ReceiptCredential_GetReceiptExpirationTime,
  ReceiptCredential_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptExpirationTime,
  ReceiptCredentialPresentation_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptSerial,
  GenericServerSecretParams_CheckValidContents,
  GenericServerSecretParams_GenerateDeterministic,
  GenericServerSecretParams_GetPublicParams,
  GenericServerPublicParams_CheckValidContents,
  CallLinkSecretParams_CheckValidContents,
  CallLinkSecretParams_DeriveFromRootKey,
  CallLinkSecretParams_GetPublicParams,
  CallLinkSecretParams_DecryptUserId,
  CallLinkSecretParams_EncryptUserId,
  CallLinkPublicParams_CheckValidContents,
  CreateCallLinkCredentialRequestContext_CheckValidContents,
  CreateCallLinkCredentialRequestContext_NewDeterministic,
  CreateCallLinkCredentialRequestContext_GetRequest,
  CreateCallLinkCredentialRequest_CheckValidContents,
  CreateCallLinkCredentialRequest_IssueDeterministic,
  CreateCallLinkCredentialResponse_CheckValidContents,
  CreateCallLinkCredentialRequestContext_ReceiveResponse,
  CreateCallLinkCredential_CheckValidContents,
  CreateCallLinkCredential_PresentDeterministic,
  CreateCallLinkCredentialPresentation_CheckValidContents,
  CreateCallLinkCredentialPresentation_Verify,
  CallLinkAuthCredentialResponse_CheckValidContents,
  CallLinkAuthCredentialResponse_IssueDeterministic,
  CallLinkAuthCredentialResponse_Receive,
  CallLinkAuthCredential_CheckValidContents,
  CallLinkAuthCredential_PresentDeterministic,
  CallLinkAuthCredentialPresentation_CheckValidContents,
  CallLinkAuthCredentialPresentation_Verify,
  CallLinkAuthCredentialPresentation_GetUserId,
  BackupAuthCredentialRequestContext_New,
  BackupAuthCredentialRequestContext_CheckValidContents,
  BackupAuthCredentialRequestContext_GetRequest,
  BackupAuthCredentialRequest_CheckValidContents,
  BackupAuthCredentialRequest_IssueDeterministic,
  BackupAuthCredentialResponse_CheckValidContents,
  BackupAuthCredentialRequestContext_ReceiveResponse,
  BackupAuthCredential_CheckValidContents,
  BackupAuthCredential_GetBackupId,
  BackupAuthCredential_GetBackupLevel,
  BackupAuthCredential_GetType,
  BackupAuthCredential_PresentDeterministic,
  BackupAuthCredentialPresentation_CheckValidContents,
  BackupAuthCredentialPresentation_Verify,
  BackupAuthCredentialPresentation_GetBackupId,
  BackupAuthCredentialPresentation_GetBackupLevel,
  BackupAuthCredentialPresentation_GetType,
  GroupSendDerivedKeyPair_CheckValidContents,
  GroupSendDerivedKeyPair_ForExpiration,
  GroupSendEndorsementsResponse_CheckValidContents,
  GroupSendEndorsementsResponse_IssueDeterministic,
  GroupSendEndorsementsResponse_GetExpiration,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts,
  GroupSendEndorsement_CheckValidContents,
  GroupSendEndorsement_Combine,
  GroupSendEndorsement_Remove,
  GroupSendEndorsement_ToToken,
  GroupSendEndorsement_CallLinkParams_ToToken,
  GroupSendToken_CheckValidContents,
  GroupSendToken_ToFullToken,
  GroupSendFullToken_CheckValidContents,
  GroupSendFullToken_GetExpiration,
  GroupSendFullToken_Verify,
  LookupRequest_new,
  LookupRequest_addE164,
  LookupRequest_addPreviousE164,
  LookupRequest_setToken,
  LookupRequest_addAciAndAccessKey,
  CdsiLookup_new,
  CdsiLookup_token,
  CdsiLookup_complete,
  HttpRequest_new,
  HttpRequest_add_header,
  ChatConnectionInfo_local_port,
  ChatConnectionInfo_ip_version,
  ChatConnectionInfo_description,
  UnauthenticatedChatConnection_connect,
  UnauthenticatedChatConnection_init_listener,
  UnauthenticatedChatConnection_send,
  UnauthenticatedChatConnection_disconnect,
  UnauthenticatedChatConnection_info,
  UnauthenticatedChatConnection_look_up_username_hash,
  UnauthenticatedChatConnection_look_up_username_link,
  UnauthenticatedChatConnection_send_multi_recipient_message,
  AuthenticatedChatConnection_preconnect,
  AuthenticatedChatConnection_connect,
  AuthenticatedChatConnection_init_listener,
  AuthenticatedChatConnection_send,
  AuthenticatedChatConnection_disconnect,
  AuthenticatedChatConnection_info,
  ServerMessageAck_SendStatus,
  ProvisioningChatConnection_connect,
  ProvisioningChatConnection_init_listener,
  ProvisioningChatConnection_info,
  ProvisioningChatConnection_disconnect,
  KeyTransparency_AciSearchKey,
  KeyTransparency_E164SearchKey,
  KeyTransparency_UsernameHashSearchKey,
  KeyTransparency_Search,
  KeyTransparency_Monitor,
  KeyTransparency_Distinguished,
  UnauthenticatedChatConnection_account_exists,
  RegistrationService_CreateSession,
  RegistrationService_ResumeSession,
  RegistrationService_RequestVerificationCode,
  RegistrationService_SubmitVerificationCode,
  RegistrationService_SubmitCaptcha,
  RegistrationService_CheckSvr2Credentials,
  RegistrationService_RegisterAccount,
  RegistrationService_ReregisterAccount,
  RegistrationService_SessionId,
  RegistrationService_RegistrationSession,
  RegistrationSession_GetAllowedToRequestCode,
  RegistrationSession_GetVerified,
  RegistrationSession_GetNextCallSeconds,
  RegistrationSession_GetNextSmsSeconds,
  RegistrationSession_GetNextVerificationAttemptSeconds,
  RegistrationSession_GetRequestedInformation,
  RegisterAccountRequest_Create,
  RegisterAccountRequest_SetSkipDeviceTransfer,
  RegisterAccountRequest_SetAccountPassword,
  RegisterAccountRequest_SetIdentityPublicKey,
  RegisterAccountRequest_SetIdentitySignedPreKey,
  RegisterAccountRequest_SetIdentityPqLastResortPreKey,
  RegistrationAccountAttributes_Create,
  RegisterAccountResponse_GetIdentity,
  RegisterAccountResponse_GetNumber,
  RegisterAccountResponse_GetUsernameHash,
  RegisterAccountResponse_GetUsernameLinkHandle,
  RegisterAccountResponse_GetStorageCapable,
  RegisterAccountResponse_GetReregistration,
  RegisterAccountResponse_GetEntitlementBadges,
  RegisterAccountResponse_GetEntitlementBackupLevel,
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds,
  SecureValueRecoveryForBackups_CreateNewBackupChain,
  SecureValueRecoveryForBackups_StoreBackup,
  SecureValueRecoveryForBackups_RestoreBackupFromServer,
  SecureValueRecoveryForBackups_RemoveBackup,
  BackupStoreResponse_GetForwardSecrecyToken,
  BackupStoreResponse_GetOpaqueMetadata,
  BackupStoreResponse_GetNextBackupSecretData,
  BackupRestoreResponse_GetForwardSecrecyToken,
  BackupRestoreResponse_GetNextBackupSecretData,
  TokioAsyncContext_new,
  TokioAsyncContext_cancel,
  ConnectionProxyConfig_new,
  ConnectionManager_new,
  ConnectionManager_set_proxy,
  ConnectionManager_set_invalid_proxy,
  ConnectionManager_clear_proxy,
  ConnectionManager_set_ipv6_enabled,
  ConnectionManager_set_censorship_circumvention_enabled,
  ConnectionManager_set_remote_config,
  ConnectionManager_on_network_change,
  AccountEntropyPool_Generate,
  AccountEntropyPool_IsValid,
  AccountEntropyPool_DeriveSvrKey,
  AccountEntropyPool_DeriveBackupKey,
  BackupKey_DeriveBackupId,
  BackupKey_DeriveEcKey,
  BackupKey_DeriveLocalBackupMetadataKey,
  BackupKey_DeriveMediaId,
  BackupKey_DeriveMediaEncryptionKey,
  BackupKey_DeriveThumbnailTransitEncryptionKey,
  IncrementalMac_CalculateChunkSize,
  IncrementalMac_Initialize,
  IncrementalMac_Update,
  IncrementalMac_Finalize,
  ValidatingMac_Initialize,
  ValidatingMac_Update,
  ValidatingMac_Finalize,
  MessageBackupKey_FromAccountEntropyPool,
  MessageBackupKey_FromBackupKeyAndBackupId,
  MessageBackupKey_GetHmacKey,
  MessageBackupKey_GetAesKey,
  MessageBackupValidator_Validate,
  OnlineBackupValidator_New,
  OnlineBackupValidator_AddFrame,
  OnlineBackupValidator_Finalize,
  BackupJsonExporter_New,
  BackupJsonExporter_GetInitialChunk,
  BackupJsonExporter_ExportFrames,
  BackupJsonExporter_Finish,
  Username_Hash,
  Username_Proof,
  Username_Verify,
  Username_CandidatesFrom,
  Username_HashFromParts,
  UsernameLink_Create,
  UsernameLink_DecryptUsername,
  SignalMedia_CheckAvailable,
  Mp4Sanitizer_Sanitize,
  WebpSanitizer_Sanitize,
  SanitizedMetadata_GetMetadata,
  SanitizedMetadata_GetDataOffset,
  SanitizedMetadata_GetDataLen,
  BridgedStringMap_new,
  BridgedStringMap_insert,
  TESTING_NonSuspendingBackgroundThreadRuntime_New,
  TESTING_FutureSuccess,
  TESTING_TokioAsyncContext_FutureSuccessBytes,
  TESTING_FutureFailure,
  TESTING_FutureCancellationCounter_Create,
  TESTING_FutureCancellationCounter_WaitForCount,
  TESTING_FutureIncrementOnCancel,
  TESTING_TokioAsyncFuture,
  TESTING_TestingHandleType_getValue,
  TESTING_FutureProducesPointerType,
  TESTING_OtherTestingHandleType_getValue,
  TESTING_FutureProducesOtherPointerType,
  TESTING_PanicOnBorrowSync,
  TESTING_PanicOnBorrowAsync,
  TESTING_PanicOnBorrowIo,
  TESTING_ErrorOnBorrowSync,
  TESTING_ErrorOnBorrowAsync,
  TESTING_ErrorOnBorrowIo,
  TESTING_PanicOnLoadSync,
  TESTING_PanicOnLoadAsync,
  TESTING_PanicOnLoadIo,
  TESTING_PanicInBodySync,
  TESTING_PanicInBodyAsync,
  TESTING_PanicInBodyIo,
  TESTING_PanicOnReturnSync,
  TESTING_PanicOnReturnAsync,
  TESTING_PanicOnReturnIo,
  TESTING_ErrorOnReturnSync,
  TESTING_ErrorOnReturnAsync,
  TESTING_ErrorOnReturnIo,
  TESTING_ReturnStringArray,
  TESTING_JoinStringArray,
  TESTING_ProcessBytestringArray,
  TESTING_RoundTripU8,
  TESTING_RoundTripU16,
  TESTING_RoundTripU32,
  TESTING_RoundTripI32,
  TESTING_RoundTripU64,
  TESTING_ConvertOptionalUuid,
  TESTING_InputStreamReadIntoZeroLengthSlice,
  ComparableBackup_ReadUnencrypted,
  ComparableBackup_GetComparableString,
  ComparableBackup_GetUnknownFields,
  TESTING_FakeChatServer_Create,
  TESTING_FakeChatServer_GetNextRemote,
  TESTING_FakeChatConnection_Create,
  TESTING_FakeChatConnection_CreateProvisioning,
  TESTING_FakeChatConnection_TakeAuthenticatedChat,
  TESTING_FakeChatConnection_TakeUnauthenticatedChat,
  TESTING_FakeChatConnection_TakeProvisioningChat,
  TESTING_FakeChatConnection_TakeRemote,
  TESTING_FakeChatRemoteEnd_SendRawServerRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerResponse,
  TESTING_FakeChatRemoteEnd_SendServerResponse,
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest,
  TESTING_ChatResponseConvert,
  TESTING_ChatRequestGetMethod,
  TESTING_ChatRequestGetPath,
  TESTING_ChatRequestGetHeaderNames,
  TESTING_ChatRequestGetHeaderValue,
  TESTING_ChatRequestGetBody,
  TESTING_FakeChatResponse_Create,
  TESTING_ChatConnectErrorConvert,
  TESTING_ChatSendErrorConvert,
  TESTING_KeyTransFatalVerificationFailure,
  TESTING_KeyTransNonFatalVerificationFailure,
  TESTING_KeyTransChatSendError,
  TESTING_RegistrationSessionInfoConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert,
  TESTING_FakeRegistrationSession_CreateSession,
  TESTING_RegisterAccountResponse_CreateTestValue,
  TESTING_RegistrationService_CreateSessionErrorConvert,
  TESTING_RegistrationService_ResumeSessionErrorConvert,
  TESTING_RegistrationService_UpdateSessionErrorConvert,
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert,
  TESTING_RegistrationService_SubmitVerificationErrorConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert,
  TESTING_RegistrationService_RegisterAccountErrorConvert,
  TESTING_CdsiLookupResponseConvert,
  TESTING_CdsiLookupErrorConvert,
  TESTING_ServerMessageAck_Create,
  TESTING_ConnectionManager_newLocalOverride,
  TESTING_ConnectionManager_isUsingProxy,
  TESTING_CreateOTP,
  TESTING_CreateOTPFromBase64,
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly,
  TestingSemaphore_New,
  TestingSemaphore_AddPermits,
  TestingValueHolder_New,
  TestingValueHolder_Get,
  TESTING_ReturnPair,
  test_only_fn_returns_123,
  TESTING_BridgedStringMap_dump_to_json,
  TESTING_TokioAsyncContext_NewSingleThreaded,
 } = native;

export { registerErrors, 
  initLogger,
  SealedSenderMultiRecipientMessage_Parse,
  MinidumpToJSONString,
  Aes256GcmSiv_New,
  Aes256GcmSiv_Encrypt,
  Aes256GcmSiv_Decrypt,
  PublicKey_HpkeSeal,
  PrivateKey_HpkeOpen,
  HKDF_DeriveSecrets,
  ServiceId_ServiceIdBinary,
  ServiceId_ServiceIdString,
  ServiceId_ServiceIdLog,
  ServiceId_ParseFromServiceIdBinary,
  ServiceId_ParseFromServiceIdString,
  ProtocolAddress_New,
  PublicKey_Deserialize,
  PublicKey_Serialize,
  PublicKey_GetPublicKeyBytes,
  ProtocolAddress_DeviceId,
  ProtocolAddress_Name,
  PublicKey_Equals,
  PublicKey_Verify,
  PrivateKey_Deserialize,
  PrivateKey_Serialize,
  PrivateKey_Generate,
  PrivateKey_GetPublicKey,
  PrivateKey_Sign,
  PrivateKey_Agree,
  KyberPublicKey_Serialize,
  KyberPublicKey_Deserialize,
  KyberSecretKey_Serialize,
  KyberSecretKey_Deserialize,
  KyberPublicKey_Equals,
  KyberKeyPair_Generate,
  KyberKeyPair_GetPublicKey,
  KyberKeyPair_GetSecretKey,
  IdentityKeyPair_Serialize,
  IdentityKeyPair_Deserialize,
  IdentityKeyPair_SignAlternateIdentity,
  IdentityKey_VerifyAlternateIdentity,
  Fingerprint_New,
  Fingerprint_ScannableEncoding,
  Fingerprint_DisplayString,
  ScannableFingerprint_Compare,
  SignalMessage_Deserialize,
  SignalMessage_GetBody,
  SignalMessage_GetSerialized,
  SignalMessage_GetCounter,
  SignalMessage_GetMessageVersion,
  SignalMessage_GetPqRatchet,
  SignalMessage_New,
  SignalMessage_VerifyMac,
  PreKeySignalMessage_New,
  PreKeySignalMessage_Deserialize,
  PreKeySignalMessage_Serialize,
  PreKeySignalMessage_GetRegistrationId,
  PreKeySignalMessage_GetSignedPreKeyId,
  PreKeySignalMessage_GetPreKeyId,
  PreKeySignalMessage_GetVersion,
  SenderKeyMessage_Deserialize,
  SenderKeyMessage_GetCipherText,
  SenderKeyMessage_Serialize,
  SenderKeyMessage_GetDistributionId,
  SenderKeyMessage_GetChainId,
  SenderKeyMessage_GetIteration,
  SenderKeyMessage_New,
  SenderKeyMessage_VerifySignature,
  SenderKeyDistributionMessage_Deserialize,
  SenderKeyDistributionMessage_GetChainKey,
  SenderKeyDistributionMessage_Serialize,
  SenderKeyDistributionMessage_GetDistributionId,
  SenderKeyDistributionMessage_GetChainId,
  SenderKeyDistributionMessage_GetIteration,
  SenderKeyDistributionMessage_New,
  DecryptionErrorMessage_Deserialize,
  DecryptionErrorMessage_GetTimestamp,
  DecryptionErrorMessage_GetDeviceId,
  DecryptionErrorMessage_Serialize,
  DecryptionErrorMessage_GetRatchetKey,
  DecryptionErrorMessage_ForOriginalMessage,
  DecryptionErrorMessage_ExtractFromSerializedContent,
  PlaintextContent_Deserialize,
  PlaintextContent_Serialize,
  PlaintextContent_GetBody,
  PlaintextContent_FromDecryptionErrorMessage,
  PreKeyBundle_New,
  PreKeyBundle_GetIdentityKey,
  PreKeyBundle_GetSignedPreKeySignature,
  PreKeyBundle_GetKyberPreKeySignature,
  PreKeyBundle_GetRegistrationId,
  PreKeyBundle_GetDeviceId,
  PreKeyBundle_GetSignedPreKeyId,
  PreKeyBundle_GetKyberPreKeyId,
  PreKeyBundle_GetPreKeyId,
  PreKeyBundle_GetPreKeyPublic,
  PreKeyBundle_GetSignedPreKeyPublic,
  PreKeyBundle_GetKyberPreKeyPublic,
  SignedPreKeyRecord_Deserialize,
  SignedPreKeyRecord_GetSignature,
  SignedPreKeyRecord_Serialize,
  SignedPreKeyRecord_GetId,
  SignedPreKeyRecord_GetTimestamp,
  SignedPreKeyRecord_GetPublicKey,
  SignedPreKeyRecord_GetPrivateKey,
  KyberPreKeyRecord_Deserialize,
  KyberPreKeyRecord_GetSignature,
  KyberPreKeyRecord_Serialize,
  KyberPreKeyRecord_GetId,
  KyberPreKeyRecord_GetTimestamp,
  KyberPreKeyRecord_GetPublicKey,
  KyberPreKeyRecord_GetSecretKey,
  KyberPreKeyRecord_GetKeyPair,
  SignedPreKeyRecord_New,
  KyberPreKeyRecord_New,
  PreKeyRecord_Deserialize,
  PreKeyRecord_Serialize,
  PreKeyRecord_GetId,
  PreKeyRecord_GetPublicKey,
  PreKeyRecord_GetPrivateKey,
  PreKeyRecord_New,
  SenderKeyRecord_Deserialize,
  SenderKeyRecord_Serialize,
  ServerCertificate_Deserialize,
  ServerCertificate_GetSerialized,
  ServerCertificate_GetCertificate,
  ServerCertificate_GetSignature,
  ServerCertificate_GetKeyId,
  ServerCertificate_GetKey,
  ServerCertificate_New,
  SenderCertificate_Deserialize,
  SenderCertificate_GetSerialized,
  SenderCertificate_GetCertificate,
  SenderCertificate_GetSignature,
  SenderCertificate_GetSenderUuid,
  SenderCertificate_GetSenderE164,
  SenderCertificate_GetExpiration,
  SenderCertificate_GetDeviceId,
  SenderCertificate_GetKey,
  SenderCertificate_Validate,
  SenderCertificate_GetServerCertificate,
  SenderCertificate_New,
  UnidentifiedSenderMessageContent_Deserialize,
  UnidentifiedSenderMessageContent_Serialize,
  UnidentifiedSenderMessageContent_GetContents,
  UnidentifiedSenderMessageContent_GetGroupId,
  UnidentifiedSenderMessageContent_GetSenderCert,
  UnidentifiedSenderMessageContent_GetMsgType,
  UnidentifiedSenderMessageContent_GetContentHint,
  UnidentifiedSenderMessageContent_New,
  CiphertextMessage_Type,
  CiphertextMessage_Serialize,
  CiphertextMessage_FromPlaintextContent,
  SessionRecord_ArchiveCurrentState,
  SessionRecord_HasUsableSenderChain,
  SessionRecord_CurrentRatchetKeyMatches,
  SessionRecord_Deserialize,
  SessionRecord_Serialize,
  SessionRecord_GetLocalRegistrationId,
  SessionRecord_GetRemoteRegistrationId,
  SealedSenderDecryptionResult_GetSenderUuid,
  SealedSenderDecryptionResult_GetSenderE164,
  SealedSenderDecryptionResult_GetDeviceId,
  SealedSenderDecryptionResult_Message,
  SessionBuilder_ProcessPreKeyBundle,
  SessionCipher_EncryptMessage,
  SessionCipher_DecryptSignalMessage,
  SessionCipher_DecryptPreKeySignalMessage,
  SealedSender_Encrypt,
  SealedSender_MultiRecipientEncrypt,
  SealedSender_MultiRecipientMessageForSingleRecipient,
  SealedSender_DecryptToUsmc,
  SealedSender_DecryptMessage,
  SenderKeyDistributionMessage_Create,
  SenderKeyDistributionMessage_Process,
  GroupCipher_EncryptMessage,
  GroupCipher_DecryptMessage,
  Cds2ClientState_New,
  HsmEnclaveClient_New,
  HsmEnclaveClient_CompleteHandshake,
  HsmEnclaveClient_EstablishedSend,
  HsmEnclaveClient_EstablishedRecv,
  HsmEnclaveClient_InitialRequest,
  SgxClientState_InitialRequest,
  SgxClientState_CompleteHandshake,
  SgxClientState_EstablishedSend,
  SgxClientState_EstablishedRecv,
  ExpiringProfileKeyCredential_CheckValidContents,
  ExpiringProfileKeyCredentialResponse_CheckValidContents,
  GroupMasterKey_CheckValidContents,
  GroupPublicParams_CheckValidContents,
  GroupSecretParams_CheckValidContents,
  ProfileKey_CheckValidContents,
  ProfileKeyCiphertext_CheckValidContents,
  ProfileKeyCommitment_CheckValidContents,
  ProfileKeyCredentialRequest_CheckValidContents,
  ProfileKeyCredentialRequestContext_CheckValidContents,
  ReceiptCredential_CheckValidContents,
  ReceiptCredentialPresentation_CheckValidContents,
  ReceiptCredentialRequest_CheckValidContents,
  ReceiptCredentialRequestContext_CheckValidContents,
  ReceiptCredentialResponse_CheckValidContents,
  UuidCiphertext_CheckValidContents,
  ServerPublicParams_Deserialize,
  ServerPublicParams_Serialize,
  ServerSecretParams_Deserialize,
  ServerSecretParams_Serialize,
  ProfileKey_GetCommitment,
  ProfileKey_GetProfileKeyVersion,
  ProfileKey_DeriveAccessKey,
  GroupSecretParams_GenerateDeterministic,
  GroupSecretParams_DeriveFromMasterKey,
  GroupSecretParams_GetMasterKey,
  GroupSecretParams_GetPublicParams,
  GroupSecretParams_EncryptServiceId,
  GroupSecretParams_DecryptServiceId,
  GroupSecretParams_EncryptProfileKey,
  GroupSecretParams_DecryptProfileKey,
  GroupSecretParams_EncryptBlobWithPaddingDeterministic,
  GroupSecretParams_DecryptBlobWithPadding,
  ServerSecretParams_GenerateDeterministic,
  ServerSecretParams_GetPublicParams,
  ServerSecretParams_SignDeterministic,
  ServerPublicParams_GetEndorsementPublicKey,
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId,
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic,
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic,
  ServerPublicParams_ReceiveExpiringProfileKeyCredential,
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic,
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic,
  ServerPublicParams_ReceiveReceiptCredential,
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic,
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic,
  AuthCredentialWithPni_CheckValidContents,
  AuthCredentialWithPniResponse_CheckValidContents,
  ServerSecretParams_VerifyAuthCredentialPresentation,
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic,
  ServerSecretParams_VerifyProfileKeyCredentialPresentation,
  ServerSecretParams_IssueReceiptCredentialDeterministic,
  ServerSecretParams_VerifyReceiptCredentialPresentation,
  GroupPublicParams_GetGroupIdentifier,
  ServerPublicParams_VerifySignature,
  AuthCredentialPresentation_CheckValidContents,
  AuthCredentialPresentation_GetUuidCiphertext,
  AuthCredentialPresentation_GetPniCiphertext,
  AuthCredentialPresentation_GetRedemptionTime,
  ProfileKeyCredentialRequestContext_GetRequest,
  ExpiringProfileKeyCredential_GetExpirationTime,
  ProfileKeyCredentialPresentation_CheckValidContents,
  ProfileKeyCredentialPresentation_GetUuidCiphertext,
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext,
  ReceiptCredentialRequestContext_GetRequest,
  ReceiptCredential_GetReceiptExpirationTime,
  ReceiptCredential_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptExpirationTime,
  ReceiptCredentialPresentation_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptSerial,
  GenericServerSecretParams_CheckValidContents,
  GenericServerSecretParams_GenerateDeterministic,
  GenericServerSecretParams_GetPublicParams,
  GenericServerPublicParams_CheckValidContents,
  CallLinkSecretParams_CheckValidContents,
  CallLinkSecretParams_DeriveFromRootKey,
  CallLinkSecretParams_GetPublicParams,
  CallLinkSecretParams_DecryptUserId,
  CallLinkSecretParams_EncryptUserId,
  CallLinkPublicParams_CheckValidContents,
  CreateCallLinkCredentialRequestContext_CheckValidContents,
  CreateCallLinkCredentialRequestContext_NewDeterministic,
  CreateCallLinkCredentialRequestContext_GetRequest,
  CreateCallLinkCredentialRequest_CheckValidContents,
  CreateCallLinkCredentialRequest_IssueDeterministic,
  CreateCallLinkCredentialResponse_CheckValidContents,
  CreateCallLinkCredentialRequestContext_ReceiveResponse,
  CreateCallLinkCredential_CheckValidContents,
  CreateCallLinkCredential_PresentDeterministic,
  CreateCallLinkCredentialPresentation_CheckValidContents,
  CreateCallLinkCredentialPresentation_Verify,
  CallLinkAuthCredentialResponse_CheckValidContents,
  CallLinkAuthCredentialResponse_IssueDeterministic,
  CallLinkAuthCredentialResponse_Receive,
  CallLinkAuthCredential_CheckValidContents,
  CallLinkAuthCredential_PresentDeterministic,
  CallLinkAuthCredentialPresentation_CheckValidContents,
  CallLinkAuthCredentialPresentation_Verify,
  CallLinkAuthCredentialPresentation_GetUserId,
  BackupAuthCredentialRequestContext_New,
  BackupAuthCredentialRequestContext_CheckValidContents,
  BackupAuthCredentialRequestContext_GetRequest,
  BackupAuthCredentialRequest_CheckValidContents,
  BackupAuthCredentialRequest_IssueDeterministic,
  BackupAuthCredentialResponse_CheckValidContents,
  BackupAuthCredentialRequestContext_ReceiveResponse,
  BackupAuthCredential_CheckValidContents,
  BackupAuthCredential_GetBackupId,
  BackupAuthCredential_GetBackupLevel,
  BackupAuthCredential_GetType,
  BackupAuthCredential_PresentDeterministic,
  BackupAuthCredentialPresentation_CheckValidContents,
  BackupAuthCredentialPresentation_Verify,
  BackupAuthCredentialPresentation_GetBackupId,
  BackupAuthCredentialPresentation_GetBackupLevel,
  BackupAuthCredentialPresentation_GetType,
  GroupSendDerivedKeyPair_CheckValidContents,
  GroupSendDerivedKeyPair_ForExpiration,
  GroupSendEndorsementsResponse_CheckValidContents,
  GroupSendEndorsementsResponse_IssueDeterministic,
  GroupSendEndorsementsResponse_GetExpiration,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts,
  GroupSendEndorsement_CheckValidContents,
  GroupSendEndorsement_Combine,
  GroupSendEndorsement_Remove,
  GroupSendEndorsement_ToToken,
  GroupSendEndorsement_CallLinkParams_ToToken,
  GroupSendToken_CheckValidContents,
  GroupSendToken_ToFullToken,
  GroupSendFullToken_CheckValidContents,
  GroupSendFullToken_GetExpiration,
  GroupSendFullToken_Verify,
  LookupRequest_new,
  LookupRequest_addE164,
  LookupRequest_addPreviousE164,
  LookupRequest_setToken,
  LookupRequest_addAciAndAccessKey,
  CdsiLookup_new,
  CdsiLookup_token,
  CdsiLookup_complete,
  HttpRequest_new,
  HttpRequest_add_header,
  ChatConnectionInfo_local_port,
  ChatConnectionInfo_ip_version,
  ChatConnectionInfo_description,
  UnauthenticatedChatConnection_connect,
  UnauthenticatedChatConnection_init_listener,
  UnauthenticatedChatConnection_send,
  UnauthenticatedChatConnection_disconnect,
  UnauthenticatedChatConnection_info,
  UnauthenticatedChatConnection_look_up_username_hash,
  UnauthenticatedChatConnection_look_up_username_link,
  UnauthenticatedChatConnection_send_multi_recipient_message,
  AuthenticatedChatConnection_preconnect,
  AuthenticatedChatConnection_connect,
  AuthenticatedChatConnection_init_listener,
  AuthenticatedChatConnection_send,
  AuthenticatedChatConnection_disconnect,
  AuthenticatedChatConnection_info,
  ServerMessageAck_SendStatus,
  ProvisioningChatConnection_connect,
  ProvisioningChatConnection_init_listener,
  ProvisioningChatConnection_info,
  ProvisioningChatConnection_disconnect,
  KeyTransparency_AciSearchKey,
  KeyTransparency_E164SearchKey,
  KeyTransparency_UsernameHashSearchKey,
  KeyTransparency_Search,
  KeyTransparency_Monitor,
  KeyTransparency_Distinguished,
  UnauthenticatedChatConnection_account_exists,
  RegistrationService_CreateSession,
  RegistrationService_ResumeSession,
  RegistrationService_RequestVerificationCode,
  RegistrationService_SubmitVerificationCode,
  RegistrationService_SubmitCaptcha,
  RegistrationService_CheckSvr2Credentials,
  RegistrationService_RegisterAccount,
  RegistrationService_ReregisterAccount,
  RegistrationService_SessionId,
  RegistrationService_RegistrationSession,
  RegistrationSession_GetAllowedToRequestCode,
  RegistrationSession_GetVerified,
  RegistrationSession_GetNextCallSeconds,
  RegistrationSession_GetNextSmsSeconds,
  RegistrationSession_GetNextVerificationAttemptSeconds,
  RegistrationSession_GetRequestedInformation,
  RegisterAccountRequest_Create,
  RegisterAccountRequest_SetSkipDeviceTransfer,
  RegisterAccountRequest_SetAccountPassword,
  RegisterAccountRequest_SetIdentityPublicKey,
  RegisterAccountRequest_SetIdentitySignedPreKey,
  RegisterAccountRequest_SetIdentityPqLastResortPreKey,
  RegistrationAccountAttributes_Create,
  RegisterAccountResponse_GetIdentity,
  RegisterAccountResponse_GetNumber,
  RegisterAccountResponse_GetUsernameHash,
  RegisterAccountResponse_GetUsernameLinkHandle,
  RegisterAccountResponse_GetStorageCapable,
  RegisterAccountResponse_GetReregistration,
  RegisterAccountResponse_GetEntitlementBadges,
  RegisterAccountResponse_GetEntitlementBackupLevel,
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds,
  SecureValueRecoveryForBackups_CreateNewBackupChain,
  SecureValueRecoveryForBackups_StoreBackup,
  SecureValueRecoveryForBackups_RestoreBackupFromServer,
  SecureValueRecoveryForBackups_RemoveBackup,
  BackupStoreResponse_GetForwardSecrecyToken,
  BackupStoreResponse_GetOpaqueMetadata,
  BackupStoreResponse_GetNextBackupSecretData,
  BackupRestoreResponse_GetForwardSecrecyToken,
  BackupRestoreResponse_GetNextBackupSecretData,
  TokioAsyncContext_new,
  TokioAsyncContext_cancel,
  ConnectionProxyConfig_new,
  ConnectionManager_new,
  ConnectionManager_set_proxy,
  ConnectionManager_set_invalid_proxy,
  ConnectionManager_clear_proxy,
  ConnectionManager_set_ipv6_enabled,
  ConnectionManager_set_censorship_circumvention_enabled,
  ConnectionManager_set_remote_config,
  ConnectionManager_on_network_change,
  AccountEntropyPool_Generate,
  AccountEntropyPool_IsValid,
  AccountEntropyPool_DeriveSvrKey,
  AccountEntropyPool_DeriveBackupKey,
  BackupKey_DeriveBackupId,
  BackupKey_DeriveEcKey,
  BackupKey_DeriveLocalBackupMetadataKey,
  BackupKey_DeriveMediaId,
  BackupKey_DeriveMediaEncryptionKey,
  BackupKey_DeriveThumbnailTransitEncryptionKey,
  IncrementalMac_CalculateChunkSize,
  IncrementalMac_Initialize,
  IncrementalMac_Update,
  IncrementalMac_Finalize,
  ValidatingMac_Initialize,
  ValidatingMac_Update,
  ValidatingMac_Finalize,
  MessageBackupKey_FromAccountEntropyPool,
  MessageBackupKey_FromBackupKeyAndBackupId,
  MessageBackupKey_GetHmacKey,
  MessageBackupKey_GetAesKey,
  MessageBackupValidator_Validate,
  OnlineBackupValidator_New,
  OnlineBackupValidator_AddFrame,
  OnlineBackupValidator_Finalize,
  BackupJsonExporter_New,
  BackupJsonExporter_GetInitialChunk,
  BackupJsonExporter_ExportFrames,
  BackupJsonExporter_Finish,
  Username_Hash,
  Username_Proof,
  Username_Verify,
  Username_CandidatesFrom,
  Username_HashFromParts,
  UsernameLink_Create,
  UsernameLink_DecryptUsername,
  SignalMedia_CheckAvailable,
  Mp4Sanitizer_Sanitize,
  WebpSanitizer_Sanitize,
  SanitizedMetadata_GetMetadata,
  SanitizedMetadata_GetDataOffset,
  SanitizedMetadata_GetDataLen,
  BridgedStringMap_new,
  BridgedStringMap_insert,
  TESTING_NonSuspendingBackgroundThreadRuntime_New,
  TESTING_FutureSuccess,
  TESTING_TokioAsyncContext_FutureSuccessBytes,
  TESTING_FutureFailure,
  TESTING_FutureCancellationCounter_Create,
  TESTING_FutureCancellationCounter_WaitForCount,
  TESTING_FutureIncrementOnCancel,
  TESTING_TokioAsyncFuture,
  TESTING_TestingHandleType_getValue,
  TESTING_FutureProducesPointerType,
  TESTING_OtherTestingHandleType_getValue,
  TESTING_FutureProducesOtherPointerType,
  TESTING_PanicOnBorrowSync,
  TESTING_PanicOnBorrowAsync,
  TESTING_PanicOnBorrowIo,
  TESTING_ErrorOnBorrowSync,
  TESTING_ErrorOnBorrowAsync,
  TESTING_ErrorOnBorrowIo,
  TESTING_PanicOnLoadSync,
  TESTING_PanicOnLoadAsync,
  TESTING_PanicOnLoadIo,
  TESTING_PanicInBodySync,
  TESTING_PanicInBodyAsync,
  TESTING_PanicInBodyIo,
  TESTING_PanicOnReturnSync,
  TESTING_PanicOnReturnAsync,
  TESTING_PanicOnReturnIo,
  TESTING_ErrorOnReturnSync,
  TESTING_ErrorOnReturnAsync,
  TESTING_ErrorOnReturnIo,
  TESTING_ReturnStringArray,
  TESTING_JoinStringArray,
  TESTING_ProcessBytestringArray,
  TESTING_RoundTripU8,
  TESTING_RoundTripU16,
  TESTING_RoundTripU32,
  TESTING_RoundTripI32,
  TESTING_RoundTripU64,
  TESTING_ConvertOptionalUuid,
  TESTING_InputStreamReadIntoZeroLengthSlice,
  ComparableBackup_ReadUnencrypted,
  ComparableBackup_GetComparableString,
  ComparableBackup_GetUnknownFields,
  TESTING_FakeChatServer_Create,
  TESTING_FakeChatServer_GetNextRemote,
  TESTING_FakeChatConnection_Create,
  TESTING_FakeChatConnection_CreateProvisioning,
  TESTING_FakeChatConnection_TakeAuthenticatedChat,
  TESTING_FakeChatConnection_TakeUnauthenticatedChat,
  TESTING_FakeChatConnection_TakeProvisioningChat,
  TESTING_FakeChatConnection_TakeRemote,
  TESTING_FakeChatRemoteEnd_SendRawServerRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerResponse,
  TESTING_FakeChatRemoteEnd_SendServerResponse,
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest,
  TESTING_ChatResponseConvert,
  TESTING_ChatRequestGetMethod,
  TESTING_ChatRequestGetPath,
  TESTING_ChatRequestGetHeaderNames,
  TESTING_ChatRequestGetHeaderValue,
  TESTING_ChatRequestGetBody,
  TESTING_FakeChatResponse_Create,
  TESTING_ChatConnectErrorConvert,
  TESTING_ChatSendErrorConvert,
  TESTING_KeyTransFatalVerificationFailure,
  TESTING_KeyTransNonFatalVerificationFailure,
  TESTING_KeyTransChatSendError,
  TESTING_RegistrationSessionInfoConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert,
  TESTING_FakeRegistrationSession_CreateSession,
  TESTING_RegisterAccountResponse_CreateTestValue,
  TESTING_RegistrationService_CreateSessionErrorConvert,
  TESTING_RegistrationService_ResumeSessionErrorConvert,
  TESTING_RegistrationService_UpdateSessionErrorConvert,
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert,
  TESTING_RegistrationService_SubmitVerificationErrorConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert,
  TESTING_RegistrationService_RegisterAccountErrorConvert,
  TESTING_CdsiLookupResponseConvert,
  TESTING_CdsiLookupErrorConvert,
  TESTING_ServerMessageAck_Create,
  TESTING_ConnectionManager_newLocalOverride,
  TESTING_ConnectionManager_isUsingProxy,
  TESTING_CreateOTP,
  TESTING_CreateOTPFromBase64,
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly,
  TestingSemaphore_New,
  TestingSemaphore_AddPermits,
  TestingValueHolder_New,
  TestingValueHolder_Get,
  TESTING_ReturnPair,
  test_only_fn_returns_123,
  TESTING_BridgedStringMap_dump_to_json,
  TESTING_TokioAsyncContext_NewSingleThreaded,
 };

/* eslint-disable comma-dangle */
export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
export interface BridgedStringMap { readonly __type: unique symbol; }
export interface Aes256GcmSiv { readonly __type: unique symbol; }
export interface HsmEnclaveClient { readonly __type: unique symbol; }
export interface LookupRequest { readonly __type: unique symbol; }
export interface CdsiLookup { readonly __type: unique symbol; }
export interface ChatConnectionInfo { readonly __type: unique symbol; }
export interface UnauthenticatedChatConnection { readonly __type: unique symbol; }
export interface AuthenticatedChatConnection { readonly __type: unique symbol; }
export interface ProvisioningChatConnection { readonly __type: unique symbol; }
export interface HttpRequest { readonly __type: unique symbol; }
export /*trait*/ type ChatListener = {
  receivedIncomingMessage: (envelope: Uint8Array, timestamp: Timestamp, ack: ServerMessageAck) => void;
  receivedQueueEmpty: () => void;
  receivedAlerts: (alerts: string[]) => void;
  connectionInterrupted: (disconnectCause: Error|null) => void;
};
export interface ServerMessageAck { readonly __type: unique symbol; }
export /*trait*/ type ProvisioningListener = {
  receivedAddress: (address: string, sendAck: ServerMessageAck) => void;
  receivedEnvelope: (envelope: Uint8Array, sendAck: ServerMessageAck) => void;
  connectionInterrupted: (disconnectCause: Error|null) => void;
};
export interface RegistrationService { readonly __type: unique symbol; }
export interface RegistrationSession { readonly __type: unique symbol; }
export interface RegisterAccountRequest { readonly __type: unique symbol; }
export interface RegisterAccountResponse { readonly __type: unique symbol; }
export interface RegistrationAccountAttributes { readonly __type: unique symbol; }
export interface BackupStoreResponse { readonly __type: unique symbol; }
export interface BackupRestoreResponse { readonly __type: unique symbol; }
export const NetRemoteConfigKeys = ['chatRequestConnectionCheckTimeoutMillis', 'disableNagleAlgorithm', 'useH2ForUnauthChat', 'grpc.AccountsAnonymousLookupUsernameHash', ] as const;
export interface TokioAsyncContext { readonly __type: unique symbol; }
export interface ConnectionManager { readonly __type: unique symbol; }
export interface ConnectionProxyConfig { readonly __type: unique symbol; }
export interface CiphertextMessage { readonly __type: unique symbol; }
export interface DecryptionErrorMessage { readonly __type: unique symbol; }
export interface Fingerprint { readonly __type: unique symbol; }
export interface PlaintextContent { readonly __type: unique symbol; }
export interface PreKeyBundle { readonly __type: unique symbol; }
export interface PreKeyRecord { readonly __type: unique symbol; }
export interface PreKeySignalMessage { readonly __type: unique symbol; }
export interface PrivateKey { readonly __type: unique symbol; }
export interface ProtocolAddress { readonly __type: unique symbol; }
export interface PublicKey { readonly __type: unique symbol; }
export interface SenderCertificate { readonly __type: unique symbol; }
export interface SenderKeyDistributionMessage { readonly __type: unique symbol; }
export interface SenderKeyMessage { readonly __type: unique symbol; }
export interface SenderKeyRecord { readonly __type: unique symbol; }
export interface ServerCertificate { readonly __type: unique symbol; }
export interface SessionRecord { readonly __type: unique symbol; }
export interface SignalMessage { readonly __type: unique symbol; }
export interface SignedPreKeyRecord { readonly __type: unique symbol; }
export interface KyberPreKeyRecord { readonly __type: unique symbol; }
export interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
export interface SealedSenderDecryptionResult { readonly __type: unique symbol; }
export interface KyberKeyPair { readonly __type: unique symbol; }
export interface KyberPublicKey { readonly __type: unique symbol; }
export interface KyberSecretKey { readonly __type: unique symbol; }
export interface SgxClientState { readonly __type: unique symbol; }
export interface ExpiringProfileKeyCredential { readonly __type: unique symbol; }
export interface ExpiringProfileKeyCredentialResponse { readonly __type: unique symbol; }
export interface GroupMasterKey { readonly __type: unique symbol; }
export interface GroupPublicParams { readonly __type: unique symbol; }
export interface GroupSecretParams { readonly __type: unique symbol; }
export interface ProfileKey { readonly __type: unique symbol; }
export interface ProfileKeyCiphertext { readonly __type: unique symbol; }
export interface ProfileKeyCommitment { readonly __type: unique symbol; }
export interface ProfileKeyCredentialRequest { readonly __type: unique symbol; }
export interface ProfileKeyCredentialRequestContext { readonly __type: unique symbol; }
export interface ReceiptCredential { readonly __type: unique symbol; }
export interface ReceiptCredentialPresentation { readonly __type: unique symbol; }
export interface ReceiptCredentialRequest { readonly __type: unique symbol; }
export interface ReceiptCredentialRequestContext { readonly __type: unique symbol; }
export interface ReceiptCredentialResponse { readonly __type: unique symbol; }
export interface UuidCiphertext { readonly __type: unique symbol; }
export interface ServerPublicParams { readonly __type: unique symbol; }
export interface ServerSecretParams { readonly __type: unique symbol; }
export interface IncrementalMac { readonly __type: unique symbol; }
export interface ValidatingMac { readonly __type: unique symbol; }
export interface MessageBackupKey { readonly __type: unique symbol; }
export interface BackupJsonExporter { readonly __type: unique symbol; }
export interface OnlineBackupValidator { readonly __type: unique symbol; }
export interface SanitizedMetadata { readonly __type: unique symbol; }
export interface NonSuspendingBackgroundThreadRuntime { readonly __type: unique symbol; }
export interface TestingHandleType { readonly __type: unique symbol; }
export interface OtherTestingHandleType { readonly __type: unique symbol; }
export interface ComparableBackup { readonly __type: unique symbol; }
export interface FakeChatConnection { readonly __type: unique symbol; }
export interface FakeChatRemoteEnd { readonly __type: unique symbol; }
export interface FakeChatServer { readonly __type: unique symbol; }
export interface FakeChatResponse { readonly __type: unique symbol; }
export interface TestingSemaphore { readonly __type: unique symbol; }
export interface TestingFutureCancellationCounter { readonly __type: unique symbol; }
export interface TestingValueHolder { readonly __type: unique symbol; }
// FFI-only opaque types (not in Node.js bridge)
export interface Aes256Ctr32 { readonly __type: unique symbol; }
export interface Aes256GcmEncryption { readonly __type: unique symbol; }
export interface Aes256GcmDecryption { readonly __type: unique symbol; }
export interface PinHash { readonly __type: unique symbol; }
export interface Sgx2Client { readonly __type: unique symbol; }
export interface MessageBackupValidator { readonly __type: unique symbol; }

