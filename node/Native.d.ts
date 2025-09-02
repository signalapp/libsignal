//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

type Uuid = Uint8Array;

/// A Native.Timestamp may be measured in seconds or in milliseconds;
/// what's important is that it's an integer less than Number.MAX_SAFE_INTEGER.
type Timestamp = number;

// Rust code produces or consumes values that conform to these interface
// definitions. They must be kept in sync to prevent bridging errors.

type LookupResponse = {
  entries: Map<string, LookupResponseEntry>;
  debugPermitsUsed: number;
};

type LookupResponseEntry = {
  readonly aci: string | undefined;
  readonly pni: string | undefined;
};

type ChatResponse = {
  status: number;
  message: string | undefined;
  headers: ReadonlyArray<[string, string]>;
  body: Uint8Array | undefined;
};

type ChatServiceDebugInfo = {
  ipType: number;
  durationMillis: number;
  connectionInfo: string;
};

type ResponseAndDebugInfo = {
  response: ChatResponse;
  debugInfo: ChatServiceDebugInfo;
};

type SealedSenderMultiRecipientMessageRecipient = {
  deviceIds: number[];
  registrationIds: number[];
  rangeOffset: number;
  rangeLen: number;
};

type SealedSenderMultiRecipientMessage = {
  recipientMap: {
    [serviceId: string]: SealedSenderMultiRecipientMessageRecipient;
  };
  excludedRecipients: string[];
  offsetOfSharedData: number;
};

enum IdentityChange {
  // This must be kept in sync with the Rust enum of the same name.
  NewOrUnchanged = 0,
  ReplacedExisting = 1,
}

type IdentityKeyStore = {
  _getIdentityKey(): Promise<PrivateKey>;
  _getLocalRegistrationId(): Promise<number>;
  _saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange>;
  _isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    sending: boolean
  ): Promise<boolean>;
  _getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
};

type SessionStore = {
  _saveSession(addr: ProtocolAddress, record: SessionRecord): Promise<void>;
  _getSession(addr: ProtocolAddress): Promise<SessionRecord | null>;
};

type PreKeyStore = {
  _savePreKey(preKeyId: number, record: PreKeyRecord): Promise<void>;
  _getPreKey(preKeyId: number): Promise<PreKeyRecord>;
  _removePreKey(preKeyId: number): Promise<void>;
};

type SignedPreKeyStore = {
  _saveSignedPreKey(
    signedPreKeyId: number,
    record: SignedPreKeyRecord
  ): Promise<void>;
  _getSignedPreKey(signedPreKeyId: number): Promise<SignedPreKeyRecord>;
};

type KyberPreKeyStore = {
  _saveKyberPreKey(
    kyberPreKeyId: number,
    record: KyberPreKeyRecord
  ): Promise<void>;
  _getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;
  _markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void>;
};

type SenderKeyStore = {
  _saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord
  ): Promise<void>;
  _getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid
  ): Promise<SenderKeyRecord | null>;
};

type InputStream = {
  _read(amount: number): Promise<Uint8Array>;
  _skip(amount: number): Promise<void>;
};

type SyncInputStream = Uint8Array;

type ChatListener = {
  _incoming_message(
    envelope: Uint8Array,
    timestamp: number,
    ack: ServerMessageAck
  ): void;
  _queue_empty(): void;
  _received_alerts(alerts: string[]): void;
  _connection_interrupted(
    // A LibSignalError or null, but not naming the type to avoid circular import dependencies.
    reason: Error | null
  ): void;
};

type ChallengeOption = 'pushChallenge' | 'captcha';

type RegistrationPushTokenType = 'apn' | 'fcm';

type RegistrationCreateSessionRequest = {
  number: string;
  push_token?: string;
  push_token_type?: RegistrationPushTokenType;
  mcc?: string;
  mnc?: string;
};

type RegisterResponseBadge = {
  id: string;
  visible: boolean;
  expirationSeconds: number;
};

type CheckSvr2CredentialsResponse = Map<
  string,
  'match' | 'no-match' | 'invalid'
>;

type SignedPublicPreKey = {
  keyId: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
};

type Wrapper<T> = Readonly<{
  _nativeHandle: T;
}>;

type MessageBackupValidationOutcome = {
  errorMessage: string | null;
  unknownFieldMessages: Array<string>;
};

type AccountEntropyPool = string;

type CancellablePromise<T> = Promise<T> & {
  _cancellationToken: bigint;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type Serialized<T> = Uint8Array;

export function registerErrors(errorsModule: Record<string, unknown>): void;

export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
export function AccountEntropyPool_DeriveBackupKey(accountEntropy: AccountEntropyPool): Uint8Array;
export function AccountEntropyPool_DeriveSvrKey(accountEntropy: AccountEntropyPool): Uint8Array;
export function AccountEntropyPool_Generate(): string;
export function AccountEntropyPool_IsValid(accountEntropy: string): boolean;
export function Aes256GcmSiv_Decrypt(aesGcmSiv: Wrapper<Aes256GcmSiv>, ctext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Uint8Array;
export function Aes256GcmSiv_Encrypt(aesGcmSivObj: Wrapper<Aes256GcmSiv>, ptext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Uint8Array;
export function Aes256GcmSiv_New(key: Uint8Array): Aes256GcmSiv;
export function AuthCredentialPresentation_CheckValidContents(presentationBytes: Uint8Array): void;
export function AuthCredentialPresentation_GetPniCiphertext(presentationBytes: Uint8Array): Serialized<UuidCiphertext>;
export function AuthCredentialPresentation_GetRedemptionTime(presentationBytes: Uint8Array): Timestamp;
export function AuthCredentialPresentation_GetUuidCiphertext(presentationBytes: Uint8Array): Serialized<UuidCiphertext>;
export function AuthCredentialWithPniResponse_CheckValidContents(bytes: Uint8Array): void;
export function AuthCredentialWithPni_CheckValidContents(bytes: Uint8Array): void;
export function AuthenticatedChatConnection_connect(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, receiveStories: boolean, languages: string[]): CancellablePromise<AuthenticatedChatConnection>;
export function AuthenticatedChatConnection_disconnect(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>): CancellablePromise<void>;
export function AuthenticatedChatConnection_info(chat: Wrapper<AuthenticatedChatConnection>): ChatConnectionInfo;
export function AuthenticatedChatConnection_init_listener(chat: Wrapper<AuthenticatedChatConnection>, listener: ChatListener): void;
export function AuthenticatedChatConnection_preconnect(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>): CancellablePromise<void>;
export function AuthenticatedChatConnection_send(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number): CancellablePromise<ChatResponse>;
export function BackupAuthCredentialPresentation_CheckValidContents(presentationBytes: Uint8Array): void;
export function BackupAuthCredentialPresentation_GetBackupId(presentationBytes: Uint8Array): Uint8Array;
export function BackupAuthCredentialPresentation_GetBackupLevel(presentationBytes: Uint8Array): number;
export function BackupAuthCredentialPresentation_GetType(presentationBytes: Uint8Array): number;
export function BackupAuthCredentialPresentation_Verify(presentationBytes: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array): void;
export function BackupAuthCredentialRequestContext_CheckValidContents(contextBytes: Uint8Array): void;
export function BackupAuthCredentialRequestContext_GetRequest(contextBytes: Uint8Array): Uint8Array;
export function BackupAuthCredentialRequestContext_New(backupKey: Uint8Array, uuid: Uuid): Uint8Array;
export function BackupAuthCredentialRequestContext_ReceiveResponse(contextBytes: Uint8Array, responseBytes: Uint8Array, expectedRedemptionTime: Timestamp, paramsBytes: Uint8Array): Uint8Array;
export function BackupAuthCredentialRequest_CheckValidContents(requestBytes: Uint8Array): void;
export function BackupAuthCredentialRequest_IssueDeterministic(requestBytes: Uint8Array, redemptionTime: Timestamp, backupLevel: number, credentialType: number, paramsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function BackupAuthCredentialResponse_CheckValidContents(responseBytes: Uint8Array): void;
export function BackupAuthCredential_CheckValidContents(paramsBytes: Uint8Array): void;
export function BackupAuthCredential_GetBackupId(credentialBytes: Uint8Array): Uint8Array;
export function BackupAuthCredential_GetBackupLevel(credentialBytes: Uint8Array): number;
export function BackupAuthCredential_GetType(credentialBytes: Uint8Array): number;
export function BackupAuthCredential_PresentDeterministic(credentialBytes: Uint8Array, serverParamsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function BackupKey_DeriveBackupId(backupKey: Uint8Array, aci: Uint8Array): Uint8Array;
export function BackupKey_DeriveEcKey(backupKey: Uint8Array, aci: Uint8Array): PrivateKey;
export function BackupKey_DeriveLocalBackupMetadataKey(backupKey: Uint8Array): Uint8Array;
export function BackupKey_DeriveMediaEncryptionKey(backupKey: Uint8Array, mediaId: Uint8Array): Uint8Array;
export function BackupKey_DeriveMediaId(backupKey: Uint8Array, mediaName: string): Uint8Array;
export function BackupKey_DeriveThumbnailTransitEncryptionKey(backupKey: Uint8Array, mediaId: Uint8Array): Uint8Array;
export function BackupRestoreResponse_GetForwardSecrecyToken(response: Wrapper<BackupRestoreResponse>): Uint8Array;
export function BackupRestoreResponse_GetNextBackupSecretData(response: Wrapper<BackupRestoreResponse>): Uint8Array;
export function BackupStoreResponse_GetForwardSecrecyToken(response: Wrapper<BackupStoreResponse>): Uint8Array;
export function BackupStoreResponse_GetNextBackupSecretData(response: Wrapper<BackupStoreResponse>): Uint8Array;
export function BackupStoreResponse_GetOpaqueMetadata(response: Wrapper<BackupStoreResponse>): Uint8Array;
export function BridgedStringMap_insert(map: Wrapper<BridgedStringMap>, key: string, value: string): void;
export function BridgedStringMap_new(initialCapacity: number): BridgedStringMap;
export function CallLinkAuthCredentialPresentation_CheckValidContents(presentationBytes: Uint8Array): void;
export function CallLinkAuthCredentialPresentation_GetUserId(presentationBytes: Uint8Array): Serialized<UuidCiphertext>;
export function CallLinkAuthCredentialPresentation_Verify(presentationBytes: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array): void;
export function CallLinkAuthCredentialResponse_CheckValidContents(responseBytes: Uint8Array): void;
export function CallLinkAuthCredentialResponse_IssueDeterministic(userId: Uint8Array, redemptionTime: Timestamp, paramsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function CallLinkAuthCredentialResponse_Receive(responseBytes: Uint8Array, userId: Uint8Array, redemptionTime: Timestamp, paramsBytes: Uint8Array): Uint8Array;
export function CallLinkAuthCredential_CheckValidContents(credentialBytes: Uint8Array): void;
export function CallLinkAuthCredential_PresentDeterministic(credentialBytes: Uint8Array, userId: Uint8Array, redemptionTime: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function CallLinkPublicParams_CheckValidContents(paramsBytes: Uint8Array): void;
export function CallLinkSecretParams_CheckValidContents(paramsBytes: Uint8Array): void;
export function CallLinkSecretParams_DecryptUserId(paramsBytes: Uint8Array, userId: Serialized<UuidCiphertext>): Uint8Array;
export function CallLinkSecretParams_DeriveFromRootKey(rootKey: Uint8Array): Uint8Array;
export function CallLinkSecretParams_EncryptUserId(paramsBytes: Uint8Array, userId: Uint8Array): Serialized<UuidCiphertext>;
export function CallLinkSecretParams_GetPublicParams(paramsBytes: Uint8Array): Uint8Array;
export function Cds2ClientState_New(mrenclave: Uint8Array, attestationMsg: Uint8Array, currentTimestamp: Timestamp): SgxClientState;
export function CdsiLookup_complete(asyncRuntime: Wrapper<TokioAsyncContext>, lookup: Wrapper<CdsiLookup>): CancellablePromise<LookupResponse>;
export function CdsiLookup_new(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, request: Wrapper<LookupRequest>): CancellablePromise<CdsiLookup>;
export function CdsiLookup_token(lookup: Wrapper<CdsiLookup>): Uint8Array;
export function ChatConnectionInfo_description(connectionInfo: Wrapper<ChatConnectionInfo>): string;
export function ChatConnectionInfo_ip_version(connectionInfo: Wrapper<ChatConnectionInfo>): number;
export function ChatConnectionInfo_local_port(connectionInfo: Wrapper<ChatConnectionInfo>): number;
export function CiphertextMessage_FromPlaintextContent(m: Wrapper<PlaintextContent>): CiphertextMessage;
export function CiphertextMessage_Serialize(obj: Wrapper<CiphertextMessage>): Uint8Array;
export function CiphertextMessage_Type(msg: Wrapper<CiphertextMessage>): number;
export function ComparableBackup_GetComparableString(backup: Wrapper<ComparableBackup>): string;
export function ComparableBackup_GetUnknownFields(backup: Wrapper<ComparableBackup>): string[];
export function ComparableBackup_ReadUnencrypted(stream: InputStream, len: bigint, purpose: number): Promise<ComparableBackup>;
export function ConnectionManager_clear_proxy(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_new(environment: number, userAgent: string, remoteConfig: Wrapper<BridgedStringMap>): ConnectionManager;
export function ConnectionManager_on_network_change(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_set_censorship_circumvention_enabled(connectionManager: Wrapper<ConnectionManager>, enabled: boolean): void;
export function ConnectionManager_set_invalid_proxy(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_set_ipv6_enabled(connectionManager: Wrapper<ConnectionManager>, ipv6Enabled: boolean): void;
export function ConnectionManager_set_proxy(connectionManager: Wrapper<ConnectionManager>, proxy: Wrapper<ConnectionProxyConfig>): void;
export function ConnectionManager_set_remote_config(connectionManager: Wrapper<ConnectionManager>, remoteConfig: Wrapper<BridgedStringMap>): void;
export function ConnectionProxyConfig_new(scheme: string, host: string, port: number, username: string | null, password: string | null): ConnectionProxyConfig;
export function CreateCallLinkCredentialPresentation_CheckValidContents(presentationBytes: Uint8Array): void;
export function CreateCallLinkCredentialPresentation_Verify(presentationBytes: Uint8Array, roomId: Uint8Array, now: Timestamp, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array): void;
export function CreateCallLinkCredentialRequestContext_CheckValidContents(contextBytes: Uint8Array): void;
export function CreateCallLinkCredentialRequestContext_GetRequest(contextBytes: Uint8Array): Uint8Array;
export function CreateCallLinkCredentialRequestContext_NewDeterministic(roomId: Uint8Array, randomness: Uint8Array): Uint8Array;
export function CreateCallLinkCredentialRequestContext_ReceiveResponse(contextBytes: Uint8Array, responseBytes: Uint8Array, userId: Uint8Array, paramsBytes: Uint8Array): Uint8Array;
export function CreateCallLinkCredentialRequest_CheckValidContents(requestBytes: Uint8Array): void;
export function CreateCallLinkCredentialRequest_IssueDeterministic(requestBytes: Uint8Array, userId: Uint8Array, timestamp: Timestamp, paramsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function CreateCallLinkCredentialResponse_CheckValidContents(responseBytes: Uint8Array): void;
export function CreateCallLinkCredential_CheckValidContents(paramsBytes: Uint8Array): void;
export function CreateCallLinkCredential_PresentDeterministic(credentialBytes: Uint8Array, roomId: Uint8Array, userId: Uint8Array, serverParamsBytes: Uint8Array, callLinkParamsBytes: Uint8Array, randomness: Uint8Array): Uint8Array;
export function DecryptionErrorMessage_Deserialize(data: Uint8Array): DecryptionErrorMessage;
export function DecryptionErrorMessage_ExtractFromSerializedContent(bytes: Uint8Array): DecryptionErrorMessage;
export function DecryptionErrorMessage_ForOriginalMessage(originalBytes: Uint8Array, originalType: number, originalTimestamp: Timestamp, originalSenderDeviceId: number): DecryptionErrorMessage;
export function DecryptionErrorMessage_GetDeviceId(obj: Wrapper<DecryptionErrorMessage>): number;
export function DecryptionErrorMessage_GetRatchetKey(m: Wrapper<DecryptionErrorMessage>): PublicKey | null;
export function DecryptionErrorMessage_GetTimestamp(obj: Wrapper<DecryptionErrorMessage>): Timestamp;
export function DecryptionErrorMessage_Serialize(obj: Wrapper<DecryptionErrorMessage>): Uint8Array;
export function ExpiringProfileKeyCredentialResponse_CheckValidContents(buffer: Uint8Array): void;
export function ExpiringProfileKeyCredential_CheckValidContents(buffer: Uint8Array): void;
export function ExpiringProfileKeyCredential_GetExpirationTime(credential: Serialized<ExpiringProfileKeyCredential>): Timestamp;
export function Fingerprint_DisplayString(obj: Wrapper<Fingerprint>): string;
export function Fingerprint_New(iterations: number, version: number, localIdentifier: Uint8Array, localKey: Wrapper<PublicKey>, remoteIdentifier: Uint8Array, remoteKey: Wrapper<PublicKey>): Fingerprint;
export function Fingerprint_ScannableEncoding(obj: Wrapper<Fingerprint>): Uint8Array;
export function GenericServerPublicParams_CheckValidContents(paramsBytes: Uint8Array): void;
export function GenericServerSecretParams_CheckValidContents(paramsBytes: Uint8Array): void;
export function GenericServerSecretParams_GenerateDeterministic(randomness: Uint8Array): Uint8Array;
export function GenericServerSecretParams_GetPublicParams(paramsBytes: Uint8Array): Uint8Array;
export function GroupCipher_DecryptMessage(sender: Wrapper<ProtocolAddress>, message: Uint8Array, store: SenderKeyStore): Promise<Uint8Array>;
export function GroupCipher_EncryptMessage(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, message: Uint8Array, store: SenderKeyStore): Promise<CiphertextMessage>;
export function GroupMasterKey_CheckValidContents(buffer: Uint8Array): void;
export function GroupPublicParams_CheckValidContents(buffer: Uint8Array): void;
export function GroupPublicParams_GetGroupIdentifier(groupPublicParams: Serialized<GroupPublicParams>): Uint8Array;
export function GroupSecretParams_CheckValidContents(buffer: Uint8Array): void;
export function GroupSecretParams_DecryptBlobWithPadding(params: Serialized<GroupSecretParams>, ciphertext: Uint8Array): Uint8Array;
export function GroupSecretParams_DecryptProfileKey(params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKeyCiphertext>, userId: Uint8Array): Serialized<ProfileKey>;
export function GroupSecretParams_DecryptServiceId(params: Serialized<GroupSecretParams>, ciphertext: Serialized<UuidCiphertext>): Uint8Array;
export function GroupSecretParams_DeriveFromMasterKey(masterKey: Serialized<GroupMasterKey>): Serialized<GroupSecretParams>;
export function GroupSecretParams_EncryptBlobWithPaddingDeterministic(params: Serialized<GroupSecretParams>, randomness: Uint8Array, plaintext: Uint8Array, paddingLen: number): Uint8Array;
export function GroupSecretParams_EncryptProfileKey(params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKey>, userId: Uint8Array): Serialized<ProfileKeyCiphertext>;
export function GroupSecretParams_EncryptServiceId(params: Serialized<GroupSecretParams>, serviceId: Uint8Array): Serialized<UuidCiphertext>;
export function GroupSecretParams_GenerateDeterministic(randomness: Uint8Array): Serialized<GroupSecretParams>;
export function GroupSecretParams_GetMasterKey(params: Serialized<GroupSecretParams>): Serialized<GroupMasterKey>;
export function GroupSecretParams_GetPublicParams(params: Serialized<GroupSecretParams>): Serialized<GroupPublicParams>;
export function GroupSendDerivedKeyPair_CheckValidContents(bytes: Uint8Array): void;
export function GroupSendDerivedKeyPair_ForExpiration(expiration: Timestamp, serverParams: Wrapper<ServerSecretParams>): Uint8Array;
export function GroupSendEndorsement_CallLinkParams_ToToken(endorsement: Uint8Array, callLinkSecretParamsSerialized: Uint8Array): Uint8Array;
export function GroupSendEndorsement_CheckValidContents(bytes: Uint8Array): void;
export function GroupSendEndorsement_Combine(endorsements: Uint8Array[]): Uint8Array;
export function GroupSendEndorsement_Remove(endorsement: Uint8Array, toRemove: Uint8Array): Uint8Array;
export function GroupSendEndorsement_ToToken(endorsement: Uint8Array, groupParams: Serialized<GroupSecretParams>): Uint8Array;
export function GroupSendEndorsementsResponse_CheckValidContents(bytes: Uint8Array): void;
export function GroupSendEndorsementsResponse_GetExpiration(responseBytes: Uint8Array): Timestamp;
export function GroupSendEndorsementsResponse_IssueDeterministic(concatenatedGroupMemberCiphertexts: Uint8Array, keyPair: Uint8Array, randomness: Uint8Array): Uint8Array;
export function GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(responseBytes: Uint8Array, concatenatedGroupMemberCiphertexts: Uint8Array, localUserCiphertext: Uint8Array, now: Timestamp, serverParams: Wrapper<ServerPublicParams>): Uint8Array[];
export function GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(responseBytes: Uint8Array, groupMembers: Uint8Array, localUser: Uint8Array, now: Timestamp, groupParams: Serialized<GroupSecretParams>, serverParams: Wrapper<ServerPublicParams>): Uint8Array[];
export function GroupSendFullToken_CheckValidContents(bytes: Uint8Array): void;
export function GroupSendFullToken_GetExpiration(token: Uint8Array): Timestamp;
export function GroupSendFullToken_Verify(token: Uint8Array, userIds: Uint8Array, now: Timestamp, keyPair: Uint8Array): void;
export function GroupSendToken_CheckValidContents(bytes: Uint8Array): void;
export function GroupSendToken_ToFullToken(token: Uint8Array, expiration: Timestamp): Uint8Array;
export function HKDF_DeriveSecrets(outputLength: number, ikm: Uint8Array, label: Uint8Array | null, salt: Uint8Array | null): Uint8Array;
export function HsmEnclaveClient_CompleteHandshake(cli: Wrapper<HsmEnclaveClient>, handshakeReceived: Uint8Array): void;
export function HsmEnclaveClient_EstablishedRecv(cli: Wrapper<HsmEnclaveClient>, receivedCiphertext: Uint8Array): Uint8Array;
export function HsmEnclaveClient_EstablishedSend(cli: Wrapper<HsmEnclaveClient>, plaintextToSend: Uint8Array): Uint8Array;
export function HsmEnclaveClient_InitialRequest(obj: Wrapper<HsmEnclaveClient>): Uint8Array;
export function HsmEnclaveClient_New(trustedPublicKey: Uint8Array, trustedCodeHashes: Uint8Array): HsmEnclaveClient;
export function HttpRequest_add_header(request: Wrapper<HttpRequest>, name: string, value: string): void;
export function HttpRequest_new(method: string, path: string, bodyAsSlice: Uint8Array | null): HttpRequest;
export function IdentityKeyPair_Deserialize(buffer: Uint8Array): {publicKey:PublicKey,privateKey:PrivateKey};
export function IdentityKeyPair_Serialize(publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>): Uint8Array;
export function IdentityKeyPair_SignAlternateIdentity(publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>, otherIdentity: Wrapper<PublicKey>): Uint8Array;
export function IdentityKey_VerifyAlternateIdentity(publicKey: Wrapper<PublicKey>, otherIdentity: Wrapper<PublicKey>, signature: Uint8Array): boolean;
export function IncrementalMac_CalculateChunkSize(dataSize: number): number;
export function IncrementalMac_Finalize(mac: Wrapper<IncrementalMac>): Uint8Array;
export function IncrementalMac_Initialize(key: Uint8Array, chunkSize: number): IncrementalMac;
export function IncrementalMac_Update(mac: Wrapper<IncrementalMac>, bytes: Uint8Array, offset: number, length: number): Uint8Array;
export function KeyTransparency_AciSearchKey(aci: Uint8Array): Uint8Array;
export function KeyTransparency_Distinguished(asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, lastDistinguishedTreeHead: Uint8Array | null): CancellablePromise<Uint8Array>;
export function KeyTransparency_E164SearchKey(e164: string): Uint8Array;
export function KeyTransparency_Monitor(asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, aci: Uint8Array, aciIdentityKey: Wrapper<PublicKey>, e164: string | null, unidentifiedAccessKey: Uint8Array | null, usernameHash: Uint8Array | null, accountData: Uint8Array | null, lastDistinguishedTreeHead: Uint8Array, isSelfMonitor: boolean): CancellablePromise<Uint8Array>;
export function KeyTransparency_Search(asyncRuntime: Wrapper<TokioAsyncContext>, environment: number, chatConnection: Wrapper<UnauthenticatedChatConnection>, aci: Uint8Array, aciIdentityKey: Wrapper<PublicKey>, e164: string | null, unidentifiedAccessKey: Uint8Array | null, usernameHash: Uint8Array | null, accountData: Uint8Array | null, lastDistinguishedTreeHead: Uint8Array): CancellablePromise<Uint8Array>;
export function KeyTransparency_UsernameHashSearchKey(hash: Uint8Array): Uint8Array;
export function KyberKeyPair_Generate(): KyberKeyPair;
export function KyberKeyPair_GetPublicKey(keyPair: Wrapper<KyberKeyPair>): KyberPublicKey;
export function KyberKeyPair_GetSecretKey(keyPair: Wrapper<KyberKeyPair>): KyberSecretKey;
export function KyberPreKeyRecord_Deserialize(data: Uint8Array): KyberPreKeyRecord;
export function KyberPreKeyRecord_GetId(obj: Wrapper<KyberPreKeyRecord>): number;
export function KyberPreKeyRecord_GetKeyPair(obj: Wrapper<KyberPreKeyRecord>): KyberKeyPair;
export function KyberPreKeyRecord_GetPublicKey(obj: Wrapper<KyberPreKeyRecord>): KyberPublicKey;
export function KyberPreKeyRecord_GetSecretKey(obj: Wrapper<KyberPreKeyRecord>): KyberSecretKey;
export function KyberPreKeyRecord_GetSignature(obj: Wrapper<KyberPreKeyRecord>): Uint8Array;
export function KyberPreKeyRecord_GetTimestamp(obj: Wrapper<KyberPreKeyRecord>): Timestamp;
export function KyberPreKeyRecord_New(id: number, timestamp: Timestamp, keyPair: Wrapper<KyberKeyPair>, signature: Uint8Array): KyberPreKeyRecord;
export function KyberPreKeyRecord_Serialize(obj: Wrapper<KyberPreKeyRecord>): Uint8Array;
export function KyberPublicKey_Deserialize(data: Uint8Array): KyberPublicKey;
export function KyberPublicKey_Equals(lhs: Wrapper<KyberPublicKey>, rhs: Wrapper<KyberPublicKey>): boolean;
export function KyberPublicKey_Serialize(obj: Wrapper<KyberPublicKey>): Uint8Array;
export function KyberSecretKey_Deserialize(data: Uint8Array): KyberSecretKey;
export function KyberSecretKey_Serialize(obj: Wrapper<KyberSecretKey>): Uint8Array;
export function LookupRequest_addAciAndAccessKey(request: Wrapper<LookupRequest>, aci: Uint8Array, accessKey: Uint8Array): void;
export function LookupRequest_addE164(request: Wrapper<LookupRequest>, e164: string): void;
export function LookupRequest_addPreviousE164(request: Wrapper<LookupRequest>, e164: string): void;
export function LookupRequest_new(): LookupRequest;
export function LookupRequest_setToken(request: Wrapper<LookupRequest>, token: Uint8Array): void;
export function MessageBackupKey_FromAccountEntropyPool(accountEntropy: AccountEntropyPool, aci: Uint8Array, forwardSecrecyToken: Uint8Array | null): MessageBackupKey;
export function MessageBackupKey_FromBackupKeyAndBackupId(backupKey: Uint8Array, backupId: Uint8Array, forwardSecrecyToken: Uint8Array | null): MessageBackupKey;
export function MessageBackupKey_GetAesKey(key: Wrapper<MessageBackupKey>): Uint8Array;
export function MessageBackupKey_GetHmacKey(key: Wrapper<MessageBackupKey>): Uint8Array;
export function MessageBackupValidator_Validate(key: Wrapper<MessageBackupKey>, firstStream: InputStream, secondStream: InputStream, len: bigint, purpose: number): Promise<MessageBackupValidationOutcome>;
export function MinidumpToJSONString(buffer: Uint8Array): string;
export function Mp4Sanitizer_Sanitize(input: InputStream, len: bigint): Promise<SanitizedMetadata>;
export function OnlineBackupValidator_AddFrame(backup: Wrapper<OnlineBackupValidator>, frame: Uint8Array): void;
export function OnlineBackupValidator_Finalize(backup: Wrapper<OnlineBackupValidator>): void;
export function OnlineBackupValidator_New(backupInfoFrame: Uint8Array, purpose: number): OnlineBackupValidator;
export function PlaintextContent_Deserialize(data: Uint8Array): PlaintextContent;
export function PlaintextContent_FromDecryptionErrorMessage(m: Wrapper<DecryptionErrorMessage>): PlaintextContent;
export function PlaintextContent_GetBody(obj: Wrapper<PlaintextContent>): Uint8Array;
export function PlaintextContent_Serialize(obj: Wrapper<PlaintextContent>): Uint8Array;
export function PreKeyBundle_GetDeviceId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetIdentityKey(p: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetKyberPreKeyId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetKyberPreKeyPublic(bundle: Wrapper<PreKeyBundle>): KyberPublicKey;
export function PreKeyBundle_GetKyberPreKeySignature(obj: Wrapper<PreKeyBundle>): Uint8Array;
export function PreKeyBundle_GetPreKeyId(obj: Wrapper<PreKeyBundle>): number | null;
export function PreKeyBundle_GetPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey | null;
export function PreKeyBundle_GetRegistrationId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetSignedPreKeySignature(obj: Wrapper<PreKeyBundle>): Uint8Array;
export function PreKeyBundle_New(registrationId: number, deviceId: number, prekeyId: number | null, prekey: Wrapper<PublicKey> | null, signedPrekeyId: number, signedPrekey: Wrapper<PublicKey>, signedPrekeySignature: Uint8Array, identityKey: Wrapper<PublicKey>, kyberPrekeyId: number, kyberPrekey: Wrapper<KyberPublicKey>, kyberPrekeySignature: Uint8Array): PreKeyBundle;
export function PreKeyRecord_Deserialize(data: Uint8Array): PreKeyRecord;
export function PreKeyRecord_GetId(obj: Wrapper<PreKeyRecord>): number;
export function PreKeyRecord_GetPrivateKey(obj: Wrapper<PreKeyRecord>): PrivateKey;
export function PreKeyRecord_GetPublicKey(obj: Wrapper<PreKeyRecord>): PublicKey;
export function PreKeyRecord_New(id: number, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>): PreKeyRecord;
export function PreKeyRecord_Serialize(obj: Wrapper<PreKeyRecord>): Uint8Array;
export function PreKeySignalMessage_Deserialize(data: Uint8Array): PreKeySignalMessage;
export function PreKeySignalMessage_GetPreKeyId(obj: Wrapper<PreKeySignalMessage>): number | null;
export function PreKeySignalMessage_GetRegistrationId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetSignedPreKeyId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetVersion(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_New(messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: Wrapper<PublicKey>, identityKey: Wrapper<PublicKey>, signalMessage: Wrapper<SignalMessage>): PreKeySignalMessage;
export function PreKeySignalMessage_Serialize(obj: Wrapper<PreKeySignalMessage>): Uint8Array;
export function PrivateKey_Agree(privateKey: Wrapper<PrivateKey>, publicKey: Wrapper<PublicKey>): Uint8Array;
export function PrivateKey_Deserialize(data: Uint8Array): PrivateKey;
export function PrivateKey_Generate(): PrivateKey;
export function PrivateKey_GetPublicKey(k: Wrapper<PrivateKey>): PublicKey;
export function PrivateKey_HpkeOpen(sk: Wrapper<PrivateKey>, ciphertext: Uint8Array, info: Uint8Array, associatedData: Uint8Array): Uint8Array;
export function PrivateKey_Serialize(obj: Wrapper<PrivateKey>): Uint8Array;
export function PrivateKey_Sign(key: Wrapper<PrivateKey>, message: Uint8Array): Uint8Array;
export function ProfileKeyCiphertext_CheckValidContents(buffer: Uint8Array): void;
export function ProfileKeyCommitment_CheckValidContents(buffer: Uint8Array): void;
export function ProfileKeyCredentialPresentation_CheckValidContents(presentationBytes: Uint8Array): void;
export function ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(presentationBytes: Uint8Array): Serialized<ProfileKeyCiphertext>;
export function ProfileKeyCredentialPresentation_GetUuidCiphertext(presentationBytes: Uint8Array): Serialized<UuidCiphertext>;
export function ProfileKeyCredentialRequestContext_CheckValidContents(buffer: Uint8Array): void;
export function ProfileKeyCredentialRequestContext_GetRequest(context: Serialized<ProfileKeyCredentialRequestContext>): Serialized<ProfileKeyCredentialRequest>;
export function ProfileKeyCredentialRequest_CheckValidContents(buffer: Uint8Array): void;
export function ProfileKey_CheckValidContents(buffer: Uint8Array): void;
export function ProfileKey_DeriveAccessKey(profileKey: Serialized<ProfileKey>): Uint8Array;
export function ProfileKey_GetCommitment(profileKey: Serialized<ProfileKey>, userId: Uint8Array): Serialized<ProfileKeyCommitment>;
export function ProfileKey_GetProfileKeyVersion(profileKey: Serialized<ProfileKey>, userId: Uint8Array): Uint8Array;
export function ProtocolAddress_DeviceId(obj: Wrapper<ProtocolAddress>): number;
export function ProtocolAddress_Name(obj: Wrapper<ProtocolAddress>): string;
export function ProtocolAddress_New(name: string, deviceId: number): ProtocolAddress;
export function PublicKey_Compare(key1: Wrapper<PublicKey>, key2: Wrapper<PublicKey>): number;
export function PublicKey_Deserialize(data: Uint8Array): PublicKey;
export function PublicKey_Equals(lhs: Wrapper<PublicKey>, rhs: Wrapper<PublicKey>): boolean;
export function PublicKey_GetPublicKeyBytes(obj: Wrapper<PublicKey>): Uint8Array;
export function PublicKey_HpkeSeal(pk: Wrapper<PublicKey>, plaintext: Uint8Array, info: Uint8Array, associatedData: Uint8Array): Uint8Array;
export function PublicKey_Serialize(obj: Wrapper<PublicKey>): Uint8Array;
export function PublicKey_Verify(key: Wrapper<PublicKey>, message: Uint8Array, signature: Uint8Array): boolean;
export function ReceiptCredentialPresentation_CheckValidContents(buffer: Uint8Array): void;
export function ReceiptCredentialPresentation_GetReceiptExpirationTime(presentation: Serialized<ReceiptCredentialPresentation>): Timestamp;
export function ReceiptCredentialPresentation_GetReceiptLevel(presentation: Serialized<ReceiptCredentialPresentation>): bigint;
export function ReceiptCredentialPresentation_GetReceiptSerial(presentation: Serialized<ReceiptCredentialPresentation>): Uint8Array;
export function ReceiptCredentialRequestContext_CheckValidContents(buffer: Uint8Array): void;
export function ReceiptCredentialRequestContext_GetRequest(requestContext: Serialized<ReceiptCredentialRequestContext>): Serialized<ReceiptCredentialRequest>;
export function ReceiptCredentialRequest_CheckValidContents(buffer: Uint8Array): void;
export function ReceiptCredentialResponse_CheckValidContents(buffer: Uint8Array): void;
export function ReceiptCredential_CheckValidContents(buffer: Uint8Array): void;
export function ReceiptCredential_GetReceiptExpirationTime(receiptCredential: Serialized<ReceiptCredential>): Timestamp;
export function ReceiptCredential_GetReceiptLevel(receiptCredential: Serialized<ReceiptCredential>): bigint;
export function RegisterAccountRequest_Create(): RegisterAccountRequest;
export function RegisterAccountRequest_SetAccountPassword(registerAccount: Wrapper<RegisterAccountRequest>, accountPassword: string): void;
export function RegisterAccountRequest_SetIdentityPqLastResortPreKey(registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, pqLastResortPreKey: SignedPublicPreKey): void;
export function RegisterAccountRequest_SetIdentityPublicKey(registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, identityKey: Wrapper<PublicKey>): void;
export function RegisterAccountRequest_SetIdentitySignedPreKey(registerAccount: Wrapper<RegisterAccountRequest>, identityType: number, signedPreKey: SignedPublicPreKey): void;
export function RegisterAccountRequest_SetSkipDeviceTransfer(registerAccount: Wrapper<RegisterAccountRequest>): void;
export function RegisterAccountResponse_GetEntitlementBackupExpirationSeconds(response: Wrapper<RegisterAccountResponse>): bigint | null;
export function RegisterAccountResponse_GetEntitlementBackupLevel(response: Wrapper<RegisterAccountResponse>): bigint | null;
export function RegisterAccountResponse_GetEntitlementBadges(response: Wrapper<RegisterAccountResponse>): RegisterResponseBadge[];
export function RegisterAccountResponse_GetIdentity(response: Wrapper<RegisterAccountResponse>, identityType: number): Uint8Array;
export function RegisterAccountResponse_GetNumber(response: Wrapper<RegisterAccountResponse>): string;
export function RegisterAccountResponse_GetReregistration(response: Wrapper<RegisterAccountResponse>): boolean;
export function RegisterAccountResponse_GetStorageCapable(response: Wrapper<RegisterAccountResponse>): boolean;
export function RegisterAccountResponse_GetUsernameHash(response: Wrapper<RegisterAccountResponse>): Uint8Array | null;
export function RegisterAccountResponse_GetUsernameLinkHandle(response: Wrapper<RegisterAccountResponse>): Uuid | null;
export function RegistrationAccountAttributes_Create(recoveryPassword: Uint8Array, aciRegistrationId: number, pniRegistrationId: number, registrationLock: string | null, unidentifiedAccessKey: Uint8Array, unrestrictedUnidentifiedAccess: boolean, capabilities: string[], discoverableByPhoneNumber: boolean): RegistrationAccountAttributes;
export function RegistrationService_CheckSvr2Credentials(asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, svrTokens: string[]): CancellablePromise<CheckSvr2CredentialsResponse>;
export function RegistrationService_CreateSession(asyncRuntime: Wrapper<TokioAsyncContext>, createSession: RegistrationCreateSessionRequest, connectChat: ConnectChatBridge): CancellablePromise<RegistrationService>;
export function RegistrationService_RegisterAccount(asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, registerAccount: Wrapper<RegisterAccountRequest>, accountAttributes: Wrapper<RegistrationAccountAttributes>): CancellablePromise<RegisterAccountResponse>;
export function RegistrationService_RegistrationSession(service: Wrapper<RegistrationService>): RegistrationSession;
export function RegistrationService_RequestVerificationCode(asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, transport: string, client: string, languages: string[]): CancellablePromise<void>;
export function RegistrationService_ReregisterAccount(asyncRuntime: Wrapper<TokioAsyncContext>, connectChat: ConnectChatBridge, number: string, registerAccount: Wrapper<RegisterAccountRequest>, accountAttributes: Wrapper<RegistrationAccountAttributes>): CancellablePromise<RegisterAccountResponse>;
export function RegistrationService_ResumeSession(asyncRuntime: Wrapper<TokioAsyncContext>, sessionId: string, number: string, connectChat: ConnectChatBridge): CancellablePromise<RegistrationService>;
export function RegistrationService_SessionId(service: Wrapper<RegistrationService>): string;
export function RegistrationService_SubmitCaptcha(asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, captchaValue: string): CancellablePromise<void>;
export function RegistrationService_SubmitVerificationCode(asyncRuntime: Wrapper<TokioAsyncContext>, service: Wrapper<RegistrationService>, code: string): CancellablePromise<void>;
export function RegistrationSession_GetAllowedToRequestCode(session: Wrapper<RegistrationSession>): boolean;
export function RegistrationSession_GetNextCallSeconds(session: Wrapper<RegistrationSession>): number | null;
export function RegistrationSession_GetNextSmsSeconds(session: Wrapper<RegistrationSession>): number | null;
export function RegistrationSession_GetNextVerificationAttemptSeconds(session: Wrapper<RegistrationSession>): number | null;
export function RegistrationSession_GetRequestedInformation(session: Wrapper<RegistrationSession>): ChallengeOption[];
export function RegistrationSession_GetVerified(session: Wrapper<RegistrationSession>): boolean;
export function SanitizedMetadata_GetDataLen(sanitized: Wrapper<SanitizedMetadata>): bigint;
export function SanitizedMetadata_GetDataOffset(sanitized: Wrapper<SanitizedMetadata>): bigint;
export function SanitizedMetadata_GetMetadata(sanitized: Wrapper<SanitizedMetadata>): Uint8Array;
export function ScannableFingerprint_Compare(fprint1: Uint8Array, fprint2: Uint8Array): boolean;
export function SealedSenderDecryptionResult_GetDeviceId(obj: Wrapper<SealedSenderDecryptionResult>): number;
export function SealedSenderDecryptionResult_GetSenderE164(obj: Wrapper<SealedSenderDecryptionResult>): string | null;
export function SealedSenderDecryptionResult_GetSenderUuid(obj: Wrapper<SealedSenderDecryptionResult>): string;
export function SealedSenderDecryptionResult_Message(obj: Wrapper<SealedSenderDecryptionResult>): Uint8Array;
export function SealedSenderMultiRecipientMessage_Parse(buffer: Uint8Array): SealedSenderMultiRecipientMessage;
export function SealedSender_DecryptMessage(message: Uint8Array, trustRoot: Wrapper<PublicKey>, timestamp: Timestamp, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore, usePqRatchet: boolean): Promise<SealedSenderDecryptionResult>;
export function SealedSender_DecryptToUsmc(ctext: Uint8Array, identityStore: IdentityKeyStore): Promise<UnidentifiedSenderMessageContent>;
export function SealedSender_Encrypt(destination: Wrapper<ProtocolAddress>, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore): Promise<Uint8Array>;
export function SealedSender_MultiRecipientEncrypt(recipients: Wrapper<ProtocolAddress>[], recipientSessions: Wrapper<SessionRecord>[], excludedRecipients: Uint8Array, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore): Promise<Uint8Array>;
export function SealedSender_MultiRecipientMessageForSingleRecipient(encodedMultiRecipientMessage: Uint8Array): Uint8Array;
export function SecureValueRecoveryForBackups_CreateNewBackupChain(environment: number, backupKey: Uint8Array): Uint8Array;
export function SecureValueRecoveryForBackups_RemoveBackup(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string): CancellablePromise<void>;
export function SecureValueRecoveryForBackups_RestoreBackupFromServer(asyncRuntime: Wrapper<TokioAsyncContext>, backupKey: Uint8Array, metadata: Uint8Array, connectionManager: Wrapper<ConnectionManager>, username: string, password: string): CancellablePromise<BackupRestoreResponse>;
export function SecureValueRecoveryForBackups_StoreBackup(asyncRuntime: Wrapper<TokioAsyncContext>, backupKey: Uint8Array, previousSecretData: Uint8Array, connectionManager: Wrapper<ConnectionManager>, username: string, password: string): CancellablePromise<BackupStoreResponse>;
export function SenderCertificate_Deserialize(data: Uint8Array): SenderCertificate;
export function SenderCertificate_GetCertificate(obj: Wrapper<SenderCertificate>): Uint8Array;
export function SenderCertificate_GetDeviceId(obj: Wrapper<SenderCertificate>): number;
export function SenderCertificate_GetExpiration(obj: Wrapper<SenderCertificate>): Timestamp;
export function SenderCertificate_GetKey(obj: Wrapper<SenderCertificate>): PublicKey;
export function SenderCertificate_GetSenderE164(obj: Wrapper<SenderCertificate>): string | null;
export function SenderCertificate_GetSenderUuid(obj: Wrapper<SenderCertificate>): string;
export function SenderCertificate_GetSerialized(obj: Wrapper<SenderCertificate>): Uint8Array;
export function SenderCertificate_GetServerCertificate(cert: Wrapper<SenderCertificate>): ServerCertificate;
export function SenderCertificate_GetSignature(obj: Wrapper<SenderCertificate>): Uint8Array;
export function SenderCertificate_New(senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: Wrapper<PublicKey>, expiration: Timestamp, signerCert: Wrapper<ServerCertificate>, signerKey: Wrapper<PrivateKey>): SenderCertificate;
export function SenderCertificate_Validate(cert: Wrapper<SenderCertificate>, trustRoots: Wrapper<PublicKey>[], time: Timestamp): boolean;
export function SenderKeyDistributionMessage_Create(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, store: SenderKeyStore): Promise<SenderKeyDistributionMessage>;
export function SenderKeyDistributionMessage_Deserialize(data: Uint8Array): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainId(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_GetChainKey(obj: Wrapper<SenderKeyDistributionMessage>): Uint8Array;
export function SenderKeyDistributionMessage_GetDistributionId(obj: Wrapper<SenderKeyDistributionMessage>): Uuid;
export function SenderKeyDistributionMessage_GetIteration(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, chainkey: Uint8Array, pk: Wrapper<PublicKey>): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Process(sender: Wrapper<ProtocolAddress>, senderKeyDistributionMessage: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore): Promise<void>;
export function SenderKeyDistributionMessage_Serialize(obj: Wrapper<SenderKeyDistributionMessage>): Uint8Array;
export function SenderKeyMessage_Deserialize(data: Uint8Array): SenderKeyMessage;
export function SenderKeyMessage_GetChainId(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_GetCipherText(obj: Wrapper<SenderKeyMessage>): Uint8Array;
export function SenderKeyMessage_GetDistributionId(obj: Wrapper<SenderKeyMessage>): Uuid;
export function SenderKeyMessage_GetIteration(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, ciphertext: Uint8Array, pk: Wrapper<PrivateKey>): SenderKeyMessage;
export function SenderKeyMessage_Serialize(obj: Wrapper<SenderKeyMessage>): Uint8Array;
export function SenderKeyMessage_VerifySignature(skm: Wrapper<SenderKeyMessage>, pubkey: Wrapper<PublicKey>): boolean;
export function SenderKeyRecord_Deserialize(data: Uint8Array): SenderKeyRecord;
export function SenderKeyRecord_Serialize(obj: Wrapper<SenderKeyRecord>): Uint8Array;
export function ServerCertificate_Deserialize(data: Uint8Array): ServerCertificate;
export function ServerCertificate_GetCertificate(obj: Wrapper<ServerCertificate>): Uint8Array;
export function ServerCertificate_GetKey(obj: Wrapper<ServerCertificate>): PublicKey;
export function ServerCertificate_GetKeyId(obj: Wrapper<ServerCertificate>): number;
export function ServerCertificate_GetSerialized(obj: Wrapper<ServerCertificate>): Uint8Array;
export function ServerCertificate_GetSignature(obj: Wrapper<ServerCertificate>): Uint8Array;
export function ServerCertificate_New(keyId: number, serverKey: Wrapper<PublicKey>, trustRoot: Wrapper<PrivateKey>): ServerCertificate;
export function ServerMessageAck_SendStatus(ack: Wrapper<ServerMessageAck>, status: number): void;
export function ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, groupSecretParams: Serialized<GroupSecretParams>, authCredentialWithPniBytes: Uint8Array): Uint8Array;
export function ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, groupSecretParams: Serialized<GroupSecretParams>, profileKeyCredential: Serialized<ExpiringProfileKeyCredential>): Uint8Array;
export function ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, userId: Uint8Array, profileKey: Serialized<ProfileKey>): Serialized<ProfileKeyCredentialRequestContext>;
export function ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, receiptCredential: Serialized<ReceiptCredential>): Serialized<ReceiptCredentialPresentation>;
export function ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Uint8Array, receiptSerial: Uint8Array): Serialized<ReceiptCredentialRequestContext>;
export function ServerPublicParams_Deserialize(buffer: Uint8Array): ServerPublicParams;
export function ServerPublicParams_GetEndorsementPublicKey(params: Wrapper<ServerPublicParams>): Uint8Array;
export function ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(params: Wrapper<ServerPublicParams>, aci: Uint8Array, pni: Uint8Array, redemptionTime: Timestamp, authCredentialWithPniResponseBytes: Uint8Array): Uint8Array;
export function ServerPublicParams_ReceiveExpiringProfileKeyCredential(serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ProfileKeyCredentialRequestContext>, response: Serialized<ExpiringProfileKeyCredentialResponse>, currentTimeInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredential>;
export function ServerPublicParams_ReceiveReceiptCredential(serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ReceiptCredentialRequestContext>, response: Serialized<ReceiptCredentialResponse>): Serialized<ReceiptCredential>;
export function ServerPublicParams_Serialize(handle: Wrapper<ServerPublicParams>): Uint8Array;
export function ServerPublicParams_VerifySignature(serverPublicParams: Wrapper<ServerPublicParams>, message: Uint8Array, notarySignature: Uint8Array): void;
export function ServerSecretParams_Deserialize(buffer: Uint8Array): ServerSecretParams;
export function ServerSecretParams_GenerateDeterministic(randomness: Uint8Array): ServerSecretParams;
export function ServerSecretParams_GetPublicParams(params: Wrapper<ServerSecretParams>): ServerPublicParams;
export function ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, aci: Uint8Array, pni: Uint8Array, redemptionTime: Timestamp): Uint8Array;
export function ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, request: Serialized<ProfileKeyCredentialRequest>, userId: Uint8Array, commitment: Serialized<ProfileKeyCommitment>, expirationInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredentialResponse>;
export function ServerSecretParams_IssueReceiptCredentialDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Uint8Array, request: Serialized<ReceiptCredentialRequest>, receiptExpirationTime: Timestamp, receiptLevel: bigint): Serialized<ReceiptCredentialResponse>;
export function ServerSecretParams_Serialize(handle: Wrapper<ServerSecretParams>): Uint8Array;
export function ServerSecretParams_SignDeterministic(params: Wrapper<ServerSecretParams>, randomness: Uint8Array, message: Uint8Array): Uint8Array;
export function ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Uint8Array, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Uint8Array, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyReceiptCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, presentation: Serialized<ReceiptCredentialPresentation>): void;
export function ServiceId_ParseFromServiceIdBinary(input: Uint8Array): Uint8Array;
export function ServiceId_ParseFromServiceIdString(input: string): Uint8Array;
export function ServiceId_ServiceIdBinary(value: Uint8Array): Uint8Array;
export function ServiceId_ServiceIdLog(value: Uint8Array): string;
export function ServiceId_ServiceIdString(value: Uint8Array): string;
export function SessionBuilder_ProcessPreKeyBundle(bundle: Wrapper<PreKeyBundle>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp, usePqRatchet: boolean): Promise<void>;
export function SessionCipher_DecryptPreKeySignalMessage(message: Wrapper<PreKeySignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore, usePqRatchet: boolean): Promise<Uint8Array>;
export function SessionCipher_DecryptSignalMessage(message: Wrapper<SignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore): Promise<Uint8Array>;
export function SessionCipher_EncryptMessage(ptext: Uint8Array, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp): Promise<CiphertextMessage>;
export function SessionRecord_ArchiveCurrentState(sessionRecord: Wrapper<SessionRecord>): void;
export function SessionRecord_CurrentRatchetKeyMatches(s: Wrapper<SessionRecord>, key: Wrapper<PublicKey>): boolean;
export function SessionRecord_Deserialize(data: Uint8Array): SessionRecord;
export function SessionRecord_GetLocalRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_GetRemoteRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_HasUsableSenderChain(s: Wrapper<SessionRecord>, now: Timestamp): boolean;
export function SessionRecord_Serialize(obj: Wrapper<SessionRecord>): Uint8Array;
export function SgxClientState_CompleteHandshake(cli: Wrapper<SgxClientState>, handshakeReceived: Uint8Array): void;
export function SgxClientState_EstablishedRecv(cli: Wrapper<SgxClientState>, receivedCiphertext: Uint8Array): Uint8Array;
export function SgxClientState_EstablishedSend(cli: Wrapper<SgxClientState>, plaintextToSend: Uint8Array): Uint8Array;
export function SgxClientState_InitialRequest(obj: Wrapper<SgxClientState>): Uint8Array;
export function SignalMedia_CheckAvailable(): void;
export function SignalMessage_Deserialize(data: Uint8Array): SignalMessage;
export function SignalMessage_GetBody(obj: Wrapper<SignalMessage>): Uint8Array;
export function SignalMessage_GetCounter(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetMessageVersion(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetPqRatchet(msg: Wrapper<SignalMessage>): Uint8Array;
export function SignalMessage_GetSerialized(obj: Wrapper<SignalMessage>): Uint8Array;
export function SignalMessage_New(messageVersion: number, macKey: Uint8Array, senderRatchetKey: Wrapper<PublicKey>, counter: number, previousCounter: number, ciphertext: Uint8Array, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, pqRatchet: Uint8Array): SignalMessage;
export function SignalMessage_VerifyMac(msg: Wrapper<SignalMessage>, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, macKey: Uint8Array): boolean;
export function SignedPreKeyRecord_Deserialize(data: Uint8Array): SignedPreKeyRecord;
export function SignedPreKeyRecord_GetId(obj: Wrapper<SignedPreKeyRecord>): number;
export function SignedPreKeyRecord_GetPrivateKey(obj: Wrapper<SignedPreKeyRecord>): PrivateKey;
export function SignedPreKeyRecord_GetPublicKey(obj: Wrapper<SignedPreKeyRecord>): PublicKey;
export function SignedPreKeyRecord_GetSignature(obj: Wrapper<SignedPreKeyRecord>): Uint8Array;
export function SignedPreKeyRecord_GetTimestamp(obj: Wrapper<SignedPreKeyRecord>): Timestamp;
export function SignedPreKeyRecord_New(id: number, timestamp: Timestamp, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>, signature: Uint8Array): SignedPreKeyRecord;
export function SignedPreKeyRecord_Serialize(obj: Wrapper<SignedPreKeyRecord>): Uint8Array;
export function TESTING_BridgedStringMap_dump_to_json(map: Wrapper<BridgedStringMap>): string;
export function TESTING_CdsiLookupErrorConvert(errorDescription: string): void;
export function TESTING_CdsiLookupResponseConvert(asyncRuntime: Wrapper<TokioAsyncContext>): CancellablePromise<LookupResponse>;
export function TESTING_ChatConnectErrorConvert(errorDescription: string): void;
export function TESTING_ChatRequestGetBody(request: Wrapper<HttpRequest>): Uint8Array;
export function TESTING_ChatRequestGetHeaderNames(request: Wrapper<HttpRequest>): string[];
export function TESTING_ChatRequestGetHeaderValue(request: Wrapper<HttpRequest>, headerName: string): string;
export function TESTING_ChatRequestGetMethod(request: Wrapper<HttpRequest>): string;
export function TESTING_ChatRequestGetPath(request: Wrapper<HttpRequest>): string;
export function TESTING_ChatResponseConvert(bodyPresent: boolean): ChatResponse;
export function TESTING_ChatSendErrorConvert(errorDescription: string): void;
export function TESTING_ConnectionManager_isUsingProxy(manager: Wrapper<ConnectionManager>): number;
export function TESTING_ConnectionManager_newLocalOverride(userAgent: string, chatPort: number, cdsiPort: number, svr2Port: number, svrBPort: number, rootCertificateDer: Uint8Array): ConnectionManager;
export function TESTING_ConvertOptionalUuid(present: boolean): Uuid | null;
export function TESTING_CreateOTP(username: string, secret: Uint8Array): string;
export function TESTING_CreateOTPFromBase64(username: string, secret: string): string;
export function TESTING_ErrorOnBorrowAsync(_input: null): Promise<void>;
export function TESTING_ErrorOnBorrowIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null): CancellablePromise<void>;
export function TESTING_ErrorOnBorrowSync(_input: null): void;
export function TESTING_ErrorOnReturnAsync(_needsCleanup: null): Promise<null>;
export function TESTING_ErrorOnReturnIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null): CancellablePromise<null>;
export function TESTING_ErrorOnReturnSync(_needsCleanup: null): null;
export function TESTING_FakeChatConnection_Create(tokio: Wrapper<TokioAsyncContext>, listener: ChatListener, alertsJoinedByNewlines: string): FakeChatConnection;
export function TESTING_FakeChatConnection_TakeAuthenticatedChat(chat: Wrapper<FakeChatConnection>): AuthenticatedChatConnection;
export function TESTING_FakeChatConnection_TakeRemote(chat: Wrapper<FakeChatConnection>): FakeChatRemoteEnd;
export function TESTING_FakeChatConnection_TakeUnauthenticatedChat(chat: Wrapper<FakeChatConnection>): UnauthenticatedChatConnection;
export function TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(chat: Wrapper<FakeChatRemoteEnd>): void;
export function TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<FakeChatRemoteEnd>): CancellablePromise<FakeChatSentRequest | null>;
export function TESTING_FakeChatRemoteEnd_SendRawServerRequest(chat: Wrapper<FakeChatRemoteEnd>, bytes: Uint8Array): void;
export function TESTING_FakeChatRemoteEnd_SendRawServerResponse(chat: Wrapper<FakeChatRemoteEnd>, bytes: Uint8Array): void;
export function TESTING_FakeChatRemoteEnd_SendServerResponse(chat: Wrapper<FakeChatRemoteEnd>, response: Wrapper<FakeChatResponse>): void;
export function TESTING_FakeChatResponse_Create(id: bigint, status: number, message: string, headers: string[], body: Uint8Array | null): FakeChatResponse;
export function TESTING_FakeChatSentRequest_RequestId(request: Wrapper<FakeChatSentRequest>): bigint;
export function TESTING_FakeChatSentRequest_TakeHttpRequest(request: Wrapper<FakeChatSentRequest>): HttpRequest;
export function TESTING_FakeChatServer_Create(): FakeChatServer;
export function TESTING_FakeChatServer_GetNextRemote(asyncRuntime: Wrapper<TokioAsyncContext>, server: Wrapper<FakeChatServer>): CancellablePromise<FakeChatRemoteEnd>;
export function TESTING_FakeRegistrationSession_CreateSession(asyncRuntime: Wrapper<TokioAsyncContext>, createSession: RegistrationCreateSessionRequest, chat: Wrapper<FakeChatServer>): CancellablePromise<RegistrationService>;
export function TESTING_FutureCancellationCounter_Create(initialValue: number): TestingFutureCancellationCounter;
export function TESTING_FutureCancellationCounter_WaitForCount(asyncRuntime: Wrapper<TokioAsyncContext>, count: Wrapper<TestingFutureCancellationCounter>, target: number): CancellablePromise<void>;
export function TESTING_FutureFailure(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: number): CancellablePromise<number>;
export function TESTING_FutureIncrementOnCancel(asyncRuntime: Wrapper<TokioAsyncContext>, _guard: TestingFutureCancellationGuard): CancellablePromise<void>;
export function TESTING_FutureProducesOtherPointerType(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: string): CancellablePromise<OtherTestingHandleType>;
export function TESTING_FutureProducesPointerType(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number): CancellablePromise<TestingHandleType>;
export function TESTING_FutureSuccess(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number): CancellablePromise<number>;
export function TESTING_InputStreamReadIntoZeroLengthSlice(capsAlphabetInput: InputStream): Promise<Uint8Array>;
export function TESTING_JoinStringArray(array: string[], joinWith: string): string;
export function TESTING_KeyTransChatSendError(): void;
export function TESTING_KeyTransFatalVerificationFailure(): void;
export function TESTING_KeyTransNonFatalVerificationFailure(): void;
export function TESTING_NonSuspendingBackgroundThreadRuntime_New(): NonSuspendingBackgroundThreadRuntime;
export function TESTING_OtherTestingHandleType_getValue(handle: Wrapper<OtherTestingHandleType>): string;
export function TESTING_PanicInBodyAsync(_input: null): Promise<void>;
export function TESTING_PanicInBodyIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null): CancellablePromise<void>;
export function TESTING_PanicInBodySync(_input: null): void;
export function TESTING_PanicOnBorrowAsync(_input: null): Promise<void>;
export function TESTING_PanicOnBorrowIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null): CancellablePromise<void>;
export function TESTING_PanicOnBorrowSync(_input: null): void;
export function TESTING_PanicOnLoadAsync(_needsCleanup: null, _input: null): Promise<void>;
export function TESTING_PanicOnLoadIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null, _input: null): CancellablePromise<void>;
export function TESTING_PanicOnLoadSync(_needsCleanup: null, _input: null): void;
export function TESTING_PanicOnReturnAsync(_needsCleanup: null): Promise<null>;
export function TESTING_PanicOnReturnIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null): CancellablePromise<null>;
export function TESTING_PanicOnReturnSync(_needsCleanup: null): null;
export function TESTING_ProcessBytestringArray(input: Uint8Array[]): Uint8Array[];
export function TESTING_RegisterAccountResponse_CreateTestValue(): RegisterAccountResponse;
export function TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert(): CheckSvr2CredentialsResponse;
export function TESTING_RegistrationService_CreateSessionErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_RegisterAccountErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_RequestVerificationCodeErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_ResumeSessionErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_SubmitVerificationErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationService_UpdateSessionErrorConvert(errorDescription: string): void;
export function TESTING_RegistrationSessionInfoConvert(): RegistrationSession;
export function TESTING_ReturnStringArray(): string[];
export function TESTING_RoundTripI32(input: number): number;
export function TESTING_RoundTripU16(input: number): number;
export function TESTING_RoundTripU32(input: number): number;
export function TESTING_RoundTripU64(input: bigint): bigint;
export function TESTING_RoundTripU8(input: number): number;
export function TESTING_ServerMessageAck_Create(): ServerMessageAck;
export function TESTING_SignedPublicPreKey_CheckBridgesCorrectly(sourcePublicKey: Wrapper<PublicKey>, signedPreKey: SignedPublicPreKey): void;
export function TESTING_TestingHandleType_getValue(handle: Wrapper<TestingHandleType>): number;
export function TESTING_TokioAsyncContext_FutureSuccessBytes(asyncRuntime: Wrapper<TokioAsyncContext>, count: number): CancellablePromise<Uint8Array>;
export function TESTING_TokioAsyncContext_NewSingleThreaded(): TokioAsyncContext;
export function TESTING_TokioAsyncFuture(asyncRuntime: Wrapper<TokioAsyncContext>, input: number): CancellablePromise<number>;
export function TestingSemaphore_AddPermits(semaphore: Wrapper<TestingSemaphore>, permits: number): void;
export function TestingSemaphore_New(initial: number): TestingSemaphore;
export function TestingValueHolder_Get(holder: Wrapper<TestingValueHolder>): number;
export function TestingValueHolder_New(value: number): TestingValueHolder;
export function TokioAsyncContext_cancel(context: Wrapper<TokioAsyncContext>, rawCancellationId: bigint): void;
export function TokioAsyncContext_new(): TokioAsyncContext;
export function UnauthenticatedChatConnection_connect(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, languages: string[]): CancellablePromise<UnauthenticatedChatConnection>;
export function UnauthenticatedChatConnection_disconnect(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>): CancellablePromise<void>;
export function UnauthenticatedChatConnection_info(chat: Wrapper<UnauthenticatedChatConnection>): ChatConnectionInfo;
export function UnauthenticatedChatConnection_init_listener(chat: Wrapper<UnauthenticatedChatConnection>, listener: ChatListener): void;
export function UnauthenticatedChatConnection_look_up_username_hash(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, hash: Uint8Array): CancellablePromise<Uuid | null>;
export function UnauthenticatedChatConnection_send(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number): CancellablePromise<ChatResponse>;
export function UnidentifiedSenderMessageContent_Deserialize(data: Uint8Array): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContentHint(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetContents(obj: Wrapper<UnidentifiedSenderMessageContent>): Uint8Array;
export function UnidentifiedSenderMessageContent_GetGroupId(obj: Wrapper<UnidentifiedSenderMessageContent>): Uint8Array | null;
export function UnidentifiedSenderMessageContent_GetMsgType(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetSenderCert(m: Wrapper<UnidentifiedSenderMessageContent>): SenderCertificate;
export function UnidentifiedSenderMessageContent_New(message: Wrapper<CiphertextMessage>, sender: Wrapper<SenderCertificate>, contentHint: number, groupId: Uint8Array | null): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_Serialize(obj: Wrapper<UnidentifiedSenderMessageContent>): Uint8Array;
export function UsernameLink_Create(username: string, entropy: Uint8Array | null): Uint8Array;
export function UsernameLink_DecryptUsername(entropy: Uint8Array, encryptedUsername: Uint8Array): string;
export function Username_CandidatesFrom(nickname: string, minLen: number, maxLen: number): string[];
export function Username_Hash(username: string): Uint8Array;
export function Username_HashFromParts(nickname: string, discriminator: string, minLen: number, maxLen: number): Uint8Array;
export function Username_Proof(username: string, randomness: Uint8Array): Uint8Array;
export function Username_Verify(proof: Uint8Array, hash: Uint8Array): void;
export function UuidCiphertext_CheckValidContents(buffer: Uint8Array): void;
export function ValidatingMac_Finalize(mac: Wrapper<ValidatingMac>): number;
export function ValidatingMac_Initialize(key: Uint8Array, chunkSize: number, digests: Uint8Array): ValidatingMac;
export function ValidatingMac_Update(mac: Wrapper<ValidatingMac>, bytes: Uint8Array, offset: number, length: number): number;
export function WebpSanitizer_Sanitize(input: SyncInputStream): void;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
export function test_only_fn_returns_123(): number;
interface Aes256GcmSiv { readonly __type: unique symbol; }
interface AuthenticatedChatConnection { readonly __type: unique symbol; }
interface BackupRestoreResponse { readonly __type: unique symbol; }
interface BackupStoreResponse { readonly __type: unique symbol; }
interface BridgedStringMap { readonly __type: unique symbol; }
interface CdsiLookup { readonly __type: unique symbol; }
interface ChatConnectionInfo { readonly __type: unique symbol; }
interface CiphertextMessage { readonly __type: unique symbol; }
interface ComparableBackup { readonly __type: unique symbol; }
interface ComparableBackup { readonly __type: unique symbol; }
interface ConnectionManager { readonly __type: unique symbol; }
interface ConnectionProxyConfig { readonly __type: unique symbol; }
interface DecryptionErrorMessage { readonly __type: unique symbol; }
interface ExpiringProfileKeyCredential { readonly __type: unique symbol; }
interface ExpiringProfileKeyCredentialResponse { readonly __type: unique symbol; }
interface FakeChatConnection { readonly __type: unique symbol; }
interface FakeChatRemoteEnd { readonly __type: unique symbol; }
interface FakeChatResponse { readonly __type: unique symbol; }
interface FakeChatSentRequest { readonly __type: unique symbol; }
interface FakeChatServer { readonly __type: unique symbol; }
interface Fingerprint { readonly __type: unique symbol; }
interface GroupMasterKey { readonly __type: unique symbol; }
interface GroupPublicParams { readonly __type: unique symbol; }
interface GroupSecretParams { readonly __type: unique symbol; }
interface HsmEnclaveClient { readonly __type: unique symbol; }
interface HttpRequest { readonly __type: unique symbol; }
interface IncrementalMac { readonly __type: unique symbol; }
interface KyberKeyPair { readonly __type: unique symbol; }
interface KyberPreKeyRecord { readonly __type: unique symbol; }
interface KyberPublicKey { readonly __type: unique symbol; }
interface KyberSecretKey { readonly __type: unique symbol; }
interface LookupRequest { readonly __type: unique symbol; }
interface MessageBackupKey { readonly __type: unique symbol; }
interface NonSuspendingBackgroundThreadRuntime { readonly __type: unique symbol; }
interface OnlineBackupValidator { readonly __type: unique symbol; }
interface OtherTestingHandleType { readonly __type: unique symbol; }
interface PlaintextContent { readonly __type: unique symbol; }
interface PreKeyBundle { readonly __type: unique symbol; }
interface PreKeyRecord { readonly __type: unique symbol; }
interface PreKeySignalMessage { readonly __type: unique symbol; }
interface PrivateKey { readonly __type: unique symbol; }
interface ProfileKey { readonly __type: unique symbol; }
interface ProfileKeyCiphertext { readonly __type: unique symbol; }
interface ProfileKeyCommitment { readonly __type: unique symbol; }
interface ProfileKeyCredentialRequest { readonly __type: unique symbol; }
interface ProfileKeyCredentialRequestContext { readonly __type: unique symbol; }
interface ProtocolAddress { readonly __type: unique symbol; }
interface PublicKey { readonly __type: unique symbol; }
interface ReceiptCredential { readonly __type: unique symbol; }
interface ReceiptCredentialPresentation { readonly __type: unique symbol; }
interface ReceiptCredentialRequest { readonly __type: unique symbol; }
interface ReceiptCredentialRequestContext { readonly __type: unique symbol; }
interface ReceiptCredentialResponse { readonly __type: unique symbol; }
interface RegisterAccountRequest { readonly __type: unique symbol; }
interface RegisterAccountResponse { readonly __type: unique symbol; }
interface RegistrationAccountAttributes { readonly __type: unique symbol; }
interface RegistrationService { readonly __type: unique symbol; }
interface RegistrationSession { readonly __type: unique symbol; }
interface SanitizedMetadata { readonly __type: unique symbol; }
interface SealedSenderDecryptionResult { readonly __type: unique symbol; }
interface SenderCertificate { readonly __type: unique symbol; }
interface SenderKeyDistributionMessage { readonly __type: unique symbol; }
interface SenderKeyMessage { readonly __type: unique symbol; }
interface SenderKeyRecord { readonly __type: unique symbol; }
interface ServerCertificate { readonly __type: unique symbol; }
interface ServerMessageAck { readonly __type: unique symbol; }
interface ServerPublicParams { readonly __type: unique symbol; }
interface ServerSecretParams { readonly __type: unique symbol; }
interface SessionRecord { readonly __type: unique symbol; }
interface SgxClientState { readonly __type: unique symbol; }
interface SignalMessage { readonly __type: unique symbol; }
interface SignedPreKeyRecord { readonly __type: unique symbol; }
interface TestingFutureCancellationCounter { readonly __type: unique symbol; }
interface TestingHandleType { readonly __type: unique symbol; }
interface TestingSemaphore { readonly __type: unique symbol; }
interface TestingValueHolder { readonly __type: unique symbol; }
interface TokioAsyncContext { readonly __type: unique symbol; }
interface UnauthenticatedChatConnection { readonly __type: unique symbol; }
interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
interface UuidCiphertext { readonly __type: unique symbol; }
interface ValidatingMac { readonly __type: unique symbol; }
