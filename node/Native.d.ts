//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

type Uuid = Buffer;

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
  body: Buffer | undefined;
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

type IdentityKeyStore = {
  _getIdentityKey(): Promise<PrivateKey>;
  _getLocalRegistrationId(): Promise<number>;
  _saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<boolean>;
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
  _read(amount: number): Promise<Buffer>;
  _skip(amount: number): Promise<void>;
};

type SyncInputStream = Buffer;

type ChatListener = {
  _incoming_message(
    envelope: Buffer,
    timestamp: number,
    ack: ServerMessageAck
  ): void;
  _queue_empty(): void;
  _connection_interrupted(
    // A LibSignalError or null, but not naming the type to avoid circular import dependencies.
    reason: Error | null
  ): void;
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
type Serialized<T> = Buffer;

export function registerErrors(errorsModule: Record<string, unknown>): void;

export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
export function AccountEntropyPool_DeriveBackupKey(accountEntropy: AccountEntropyPool): Buffer;
export function AccountEntropyPool_DeriveSvrKey(accountEntropy: AccountEntropyPool): Buffer;
export function AccountEntropyPool_Generate(): string;
export function AccountEntropyPool_IsValid(accountEntropy: string): boolean;
export function Aes256GcmSiv_Decrypt(aesGcmSiv: Wrapper<Aes256GcmSiv>, ctext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_Encrypt(aesGcmSivObj: Wrapper<Aes256GcmSiv>, ptext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_New(key: Buffer): Aes256GcmSiv;
export function AuthCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function AuthCredentialPresentation_GetPniCiphertext(presentationBytes: Buffer): Serialized<UuidCiphertext>;
export function AuthCredentialPresentation_GetRedemptionTime(presentationBytes: Buffer): Timestamp;
export function AuthCredentialPresentation_GetUuidCiphertext(presentationBytes: Buffer): Serialized<UuidCiphertext>;
export function AuthCredentialWithPniResponse_CheckValidContents(bytes: Buffer): void;
export function AuthCredentialWithPni_CheckValidContents(bytes: Buffer): void;
export function AuthenticatedChatConnection_connect(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, receiveStories: boolean): CancellablePromise<AuthenticatedChatConnection>;
export function AuthenticatedChatConnection_disconnect(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>): CancellablePromise<void>;
export function AuthenticatedChatConnection_info(chat: Wrapper<AuthenticatedChatConnection>): ChatConnectionInfo;
export function AuthenticatedChatConnection_init_listener(chat: Wrapper<AuthenticatedChatConnection>, listener: ChatListener): void;
export function AuthenticatedChatConnection_send(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<AuthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number): CancellablePromise<ChatResponse>;
export function BackupAuthCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function BackupAuthCredentialPresentation_GetBackupId(presentationBytes: Buffer): Buffer;
export function BackupAuthCredentialPresentation_GetBackupLevel(presentationBytes: Buffer): number;
export function BackupAuthCredentialPresentation_GetType(presentationBytes: Buffer): number;
export function BackupAuthCredentialPresentation_Verify(presentationBytes: Buffer, now: Timestamp, serverParamsBytes: Buffer): void;
export function BackupAuthCredentialRequestContext_CheckValidContents(contextBytes: Buffer): void;
export function BackupAuthCredentialRequestContext_GetRequest(contextBytes: Buffer): Buffer;
export function BackupAuthCredentialRequestContext_New(backupKey: Buffer, uuid: Uuid): Buffer;
export function BackupAuthCredentialRequestContext_ReceiveResponse(contextBytes: Buffer, responseBytes: Buffer, expectedRedemptionTime: Timestamp, paramsBytes: Buffer): Buffer;
export function BackupAuthCredentialRequest_CheckValidContents(requestBytes: Buffer): void;
export function BackupAuthCredentialRequest_IssueDeterministic(requestBytes: Buffer, redemptionTime: Timestamp, backupLevel: number, credentialType: number, paramsBytes: Buffer, randomness: Buffer): Buffer;
export function BackupAuthCredentialResponse_CheckValidContents(responseBytes: Buffer): void;
export function BackupAuthCredential_CheckValidContents(paramsBytes: Buffer): void;
export function BackupAuthCredential_GetBackupId(credentialBytes: Buffer): Buffer;
export function BackupAuthCredential_GetBackupLevel(credentialBytes: Buffer): number;
export function BackupAuthCredential_GetType(credentialBytes: Buffer): number;
export function BackupAuthCredential_PresentDeterministic(credentialBytes: Buffer, serverParamsBytes: Buffer, randomness: Buffer): Buffer;
export function BackupKey_DeriveBackupId(backupKey: Buffer, aci: Buffer): Buffer;
export function BackupKey_DeriveEcKey(backupKey: Buffer, aci: Buffer): PrivateKey;
export function BackupKey_DeriveLocalBackupMetadataKey(backupKey: Buffer): Buffer;
export function BackupKey_DeriveMediaEncryptionKey(backupKey: Buffer, mediaId: Buffer): Buffer;
export function BackupKey_DeriveMediaId(backupKey: Buffer, mediaName: string): Buffer;
export function BackupKey_DeriveThumbnailTransitEncryptionKey(backupKey: Buffer, mediaId: Buffer): Buffer;
export function CallLinkAuthCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function CallLinkAuthCredentialPresentation_GetUserId(presentationBytes: Buffer): Serialized<UuidCiphertext>;
export function CallLinkAuthCredentialPresentation_Verify(presentationBytes: Buffer, now: Timestamp, serverParamsBytes: Buffer, callLinkParamsBytes: Buffer): void;
export function CallLinkAuthCredentialResponse_CheckValidContents(responseBytes: Buffer): void;
export function CallLinkAuthCredentialResponse_IssueDeterministic(userId: Buffer, redemptionTime: Timestamp, paramsBytes: Buffer, randomness: Buffer): Buffer;
export function CallLinkAuthCredentialResponse_Receive(responseBytes: Buffer, userId: Buffer, redemptionTime: Timestamp, paramsBytes: Buffer): Buffer;
export function CallLinkAuthCredential_CheckValidContents(credentialBytes: Buffer): void;
export function CallLinkAuthCredential_PresentDeterministic(credentialBytes: Buffer, userId: Buffer, redemptionTime: Timestamp, serverParamsBytes: Buffer, callLinkParamsBytes: Buffer, randomness: Buffer): Buffer;
export function CallLinkPublicParams_CheckValidContents(paramsBytes: Buffer): void;
export function CallLinkSecretParams_CheckValidContents(paramsBytes: Buffer): void;
export function CallLinkSecretParams_DecryptUserId(paramsBytes: Buffer, userId: Serialized<UuidCiphertext>): Buffer;
export function CallLinkSecretParams_DeriveFromRootKey(rootKey: Buffer): Buffer;
export function CallLinkSecretParams_GetPublicParams(paramsBytes: Buffer): Buffer;
export function Cds2ClientState_New(mrenclave: Buffer, attestationMsg: Buffer, currentTimestamp: Timestamp): SgxClientState;
export function CdsiLookup_complete(asyncRuntime: Wrapper<TokioAsyncContext>, lookup: Wrapper<CdsiLookup>): CancellablePromise<LookupResponse>;
export function CdsiLookup_new(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, request: Wrapper<LookupRequest>): CancellablePromise<CdsiLookup>;
export function CdsiLookup_new_routes(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>, username: string, password: string, request: Wrapper<LookupRequest>): CancellablePromise<CdsiLookup>;
export function CdsiLookup_token(lookup: Wrapper<CdsiLookup>): Buffer;
export function ChatConnectionInfo_description(connectionInfo: Wrapper<ChatConnectionInfo>): string;
export function ChatConnectionInfo_ip_version(connectionInfo: Wrapper<ChatConnectionInfo>): number;
export function ChatConnectionInfo_local_port(connectionInfo: Wrapper<ChatConnectionInfo>): number;
export function CiphertextMessage_FromPlaintextContent(m: Wrapper<PlaintextContent>): CiphertextMessage;
export function CiphertextMessage_Serialize(obj: Wrapper<CiphertextMessage>): Buffer;
export function CiphertextMessage_Type(msg: Wrapper<CiphertextMessage>): number;
export function ComparableBackup_GetComparableString(backup: Wrapper<ComparableBackup>): string;
export function ComparableBackup_GetUnknownFields(backup: Wrapper<ComparableBackup>): string[];
export function ComparableBackup_ReadUnencrypted(stream: InputStream, len: bigint, purpose: number): Promise<ComparableBackup>;
export function ConnectionManager_clear_proxy(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_new(environment: number, userAgent: string): ConnectionManager;
export function ConnectionManager_on_network_change(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_set_censorship_circumvention_enabled(connectionManager: Wrapper<ConnectionManager>, enabled: boolean): void;
export function ConnectionManager_set_invalid_proxy(connectionManager: Wrapper<ConnectionManager>): void;
export function ConnectionManager_set_ipv6_enabled(connectionManager: Wrapper<ConnectionManager>, ipv6Enabled: boolean): void;
export function ConnectionManager_set_proxy(connectionManager: Wrapper<ConnectionManager>, proxy: Wrapper<ConnectionProxyConfig>): void;
export function ConnectionProxyConfig_new(scheme: string, host: string, port: number, username: string | null, password: string | null): ConnectionProxyConfig;
export function CreateCallLinkCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function CreateCallLinkCredentialPresentation_Verify(presentationBytes: Buffer, roomId: Buffer, now: Timestamp, serverParamsBytes: Buffer, callLinkParamsBytes: Buffer): void;
export function CreateCallLinkCredentialRequestContext_CheckValidContents(contextBytes: Buffer): void;
export function CreateCallLinkCredentialRequestContext_GetRequest(contextBytes: Buffer): Buffer;
export function CreateCallLinkCredentialRequestContext_NewDeterministic(roomId: Buffer, randomness: Buffer): Buffer;
export function CreateCallLinkCredentialRequestContext_ReceiveResponse(contextBytes: Buffer, responseBytes: Buffer, userId: Buffer, paramsBytes: Buffer): Buffer;
export function CreateCallLinkCredentialRequest_CheckValidContents(requestBytes: Buffer): void;
export function CreateCallLinkCredentialRequest_IssueDeterministic(requestBytes: Buffer, userId: Buffer, timestamp: Timestamp, paramsBytes: Buffer, randomness: Buffer): Buffer;
export function CreateCallLinkCredentialResponse_CheckValidContents(responseBytes: Buffer): void;
export function CreateCallLinkCredential_CheckValidContents(paramsBytes: Buffer): void;
export function CreateCallLinkCredential_PresentDeterministic(credentialBytes: Buffer, roomId: Buffer, userId: Buffer, serverParamsBytes: Buffer, callLinkParamsBytes: Buffer, randomness: Buffer): Buffer;
export function CreateOTP(username: string, secret: Buffer): string;
export function CreateOTPFromBase64(username: string, secret: string): string;
export function DecryptionErrorMessage_Deserialize(data: Buffer): DecryptionErrorMessage;
export function DecryptionErrorMessage_ExtractFromSerializedContent(bytes: Buffer): DecryptionErrorMessage;
export function DecryptionErrorMessage_ForOriginalMessage(originalBytes: Buffer, originalType: number, originalTimestamp: Timestamp, originalSenderDeviceId: number): DecryptionErrorMessage;
export function DecryptionErrorMessage_GetDeviceId(obj: Wrapper<DecryptionErrorMessage>): number;
export function DecryptionErrorMessage_GetRatchetKey(m: Wrapper<DecryptionErrorMessage>): PublicKey | null;
export function DecryptionErrorMessage_GetTimestamp(obj: Wrapper<DecryptionErrorMessage>): Timestamp;
export function DecryptionErrorMessage_Serialize(obj: Wrapper<DecryptionErrorMessage>): Buffer;
export function ExpiringProfileKeyCredentialResponse_CheckValidContents(buffer: Buffer): void;
export function ExpiringProfileKeyCredential_CheckValidContents(buffer: Buffer): void;
export function ExpiringProfileKeyCredential_GetExpirationTime(credential: Serialized<ExpiringProfileKeyCredential>): Timestamp;
export function Fingerprint_DisplayString(obj: Wrapper<Fingerprint>): string;
export function Fingerprint_New(iterations: number, version: number, localIdentifier: Buffer, localKey: Wrapper<PublicKey>, remoteIdentifier: Buffer, remoteKey: Wrapper<PublicKey>): Fingerprint;
export function Fingerprint_ScannableEncoding(obj: Wrapper<Fingerprint>): Buffer;
export function GenericServerPublicParams_CheckValidContents(paramsBytes: Buffer): void;
export function GenericServerSecretParams_CheckValidContents(paramsBytes: Buffer): void;
export function GenericServerSecretParams_GenerateDeterministic(randomness: Buffer): Buffer;
export function GenericServerSecretParams_GetPublicParams(paramsBytes: Buffer): Buffer;
export function GroupCipher_DecryptMessage(sender: Wrapper<ProtocolAddress>, message: Buffer, store: SenderKeyStore): Promise<Buffer>;
export function GroupCipher_EncryptMessage(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, message: Buffer, store: SenderKeyStore): Promise<CiphertextMessage>;
export function GroupMasterKey_CheckValidContents(buffer: Buffer): void;
export function GroupPublicParams_CheckValidContents(buffer: Buffer): void;
export function GroupPublicParams_GetGroupIdentifier(groupPublicParams: Serialized<GroupPublicParams>): Buffer;
export function GroupSecretParams_CheckValidContents(buffer: Buffer): void;
export function GroupSecretParams_DecryptBlobWithPadding(params: Serialized<GroupSecretParams>, ciphertext: Buffer): Buffer;
export function GroupSecretParams_DecryptProfileKey(params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKeyCiphertext>, userId: Buffer): Serialized<ProfileKey>;
export function GroupSecretParams_DecryptServiceId(params: Serialized<GroupSecretParams>, ciphertext: Serialized<UuidCiphertext>): Buffer;
export function GroupSecretParams_DeriveFromMasterKey(masterKey: Serialized<GroupMasterKey>): Serialized<GroupSecretParams>;
export function GroupSecretParams_EncryptBlobWithPaddingDeterministic(params: Serialized<GroupSecretParams>, randomness: Buffer, plaintext: Buffer, paddingLen: number): Buffer;
export function GroupSecretParams_EncryptProfileKey(params: Serialized<GroupSecretParams>, profileKey: Serialized<ProfileKey>, userId: Buffer): Serialized<ProfileKeyCiphertext>;
export function GroupSecretParams_EncryptServiceId(params: Serialized<GroupSecretParams>, serviceId: Buffer): Serialized<UuidCiphertext>;
export function GroupSecretParams_GenerateDeterministic(randomness: Buffer): Serialized<GroupSecretParams>;
export function GroupSecretParams_GetMasterKey(params: Serialized<GroupSecretParams>): Serialized<GroupMasterKey>;
export function GroupSecretParams_GetPublicParams(params: Serialized<GroupSecretParams>): Serialized<GroupPublicParams>;
export function GroupSendDerivedKeyPair_CheckValidContents(bytes: Buffer): void;
export function GroupSendDerivedKeyPair_ForExpiration(expiration: Timestamp, serverParams: Wrapper<ServerSecretParams>): Buffer;
export function GroupSendEndorsement_CheckValidContents(bytes: Buffer): void;
export function GroupSendEndorsement_Combine(endorsements: Buffer[]): Buffer;
export function GroupSendEndorsement_Remove(endorsement: Buffer, toRemove: Buffer): Buffer;
export function GroupSendEndorsement_ToToken(endorsement: Buffer, groupParams: Serialized<GroupSecretParams>): Buffer;
export function GroupSendEndorsementsResponse_CheckValidContents(bytes: Buffer): void;
export function GroupSendEndorsementsResponse_GetExpiration(responseBytes: Buffer): Timestamp;
export function GroupSendEndorsementsResponse_IssueDeterministic(concatenatedGroupMemberCiphertexts: Buffer, keyPair: Buffer, randomness: Buffer): Buffer;
export function GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(responseBytes: Buffer, concatenatedGroupMemberCiphertexts: Buffer, localUserCiphertext: Buffer, now: Timestamp, serverParams: Wrapper<ServerPublicParams>): Buffer[];
export function GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(responseBytes: Buffer, groupMembers: Buffer, localUser: Buffer, now: Timestamp, groupParams: Serialized<GroupSecretParams>, serverParams: Wrapper<ServerPublicParams>): Buffer[];
export function GroupSendFullToken_CheckValidContents(bytes: Buffer): void;
export function GroupSendFullToken_GetExpiration(token: Buffer): Timestamp;
export function GroupSendFullToken_Verify(token: Buffer, userIds: Buffer, now: Timestamp, keyPair: Buffer): void;
export function GroupSendToken_CheckValidContents(bytes: Buffer): void;
export function GroupSendToken_ToFullToken(token: Buffer, expiration: Timestamp): Buffer;
export function HKDF_DeriveSecrets(outputLength: number, ikm: Buffer, label: Buffer | null, salt: Buffer | null): Buffer;
export function HsmEnclaveClient_CompleteHandshake(cli: Wrapper<HsmEnclaveClient>, handshakeReceived: Buffer): void;
export function HsmEnclaveClient_EstablishedRecv(cli: Wrapper<HsmEnclaveClient>, receivedCiphertext: Buffer): Buffer;
export function HsmEnclaveClient_EstablishedSend(cli: Wrapper<HsmEnclaveClient>, plaintextToSend: Buffer): Buffer;
export function HsmEnclaveClient_InitialRequest(obj: Wrapper<HsmEnclaveClient>): Buffer;
export function HsmEnclaveClient_New(trustedPublicKey: Buffer, trustedCodeHashes: Buffer): HsmEnclaveClient;
export function HttpRequest_add_header(request: Wrapper<HttpRequest>, name: string, value: string): void;
export function HttpRequest_new(method: string, path: string, bodyAsSlice: Buffer | null): HttpRequest;
export function IdentityKeyPair_Deserialize(buffer: Buffer): {publicKey:PublicKey,privateKey:PrivateKey};
export function IdentityKeyPair_Serialize(publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>): Buffer;
export function IdentityKeyPair_SignAlternateIdentity(publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>, otherIdentity: Wrapper<PublicKey>): Buffer;
export function IdentityKey_VerifyAlternateIdentity(publicKey: Wrapper<PublicKey>, otherIdentity: Wrapper<PublicKey>, signature: Buffer): boolean;
export function IncrementalMac_CalculateChunkSize(dataSize: number): number;
export function IncrementalMac_Finalize(mac: Wrapper<IncrementalMac>): Buffer;
export function IncrementalMac_Initialize(key: Buffer, chunkSize: number): IncrementalMac;
export function IncrementalMac_Update(mac: Wrapper<IncrementalMac>, bytes: Buffer, offset: number, length: number): Buffer;
export function KyberKeyPair_Generate(): KyberKeyPair;
export function KyberKeyPair_GetPublicKey(keyPair: Wrapper<KyberKeyPair>): KyberPublicKey;
export function KyberKeyPair_GetSecretKey(keyPair: Wrapper<KyberKeyPair>): KyberSecretKey;
export function KyberPreKeyRecord_Deserialize(data: Buffer): KyberPreKeyRecord;
export function KyberPreKeyRecord_GetId(obj: Wrapper<KyberPreKeyRecord>): number;
export function KyberPreKeyRecord_GetKeyPair(obj: Wrapper<KyberPreKeyRecord>): KyberKeyPair;
export function KyberPreKeyRecord_GetPublicKey(obj: Wrapper<KyberPreKeyRecord>): KyberPublicKey;
export function KyberPreKeyRecord_GetSecretKey(obj: Wrapper<KyberPreKeyRecord>): KyberSecretKey;
export function KyberPreKeyRecord_GetSignature(obj: Wrapper<KyberPreKeyRecord>): Buffer;
export function KyberPreKeyRecord_GetTimestamp(obj: Wrapper<KyberPreKeyRecord>): Timestamp;
export function KyberPreKeyRecord_New(id: number, timestamp: Timestamp, keyPair: Wrapper<KyberKeyPair>, signature: Buffer): KyberPreKeyRecord;
export function KyberPreKeyRecord_Serialize(obj: Wrapper<KyberPreKeyRecord>): Buffer;
export function KyberPublicKey_Deserialize(data: Buffer): KyberPublicKey;
export function KyberPublicKey_Equals(lhs: Wrapper<KyberPublicKey>, rhs: Wrapper<KyberPublicKey>): boolean;
export function KyberPublicKey_Serialize(obj: Wrapper<KyberPublicKey>): Buffer;
export function KyberSecretKey_Deserialize(data: Buffer): KyberSecretKey;
export function KyberSecretKey_Serialize(obj: Wrapper<KyberSecretKey>): Buffer;
export function LookupRequest_addAciAndAccessKey(request: Wrapper<LookupRequest>, aci: Buffer, accessKey: Buffer): void;
export function LookupRequest_addE164(request: Wrapper<LookupRequest>, e164: string): void;
export function LookupRequest_addPreviousE164(request: Wrapper<LookupRequest>, e164: string): void;
export function LookupRequest_new(): LookupRequest;
export function LookupRequest_setToken(request: Wrapper<LookupRequest>, token: Buffer): void;
export function MessageBackupKey_FromAccountEntropyPool(accountEntropy: AccountEntropyPool, aci: Buffer): MessageBackupKey;
export function MessageBackupKey_FromBackupKeyAndBackupId(backupKey: Buffer, backupId: Buffer): MessageBackupKey;
export function MessageBackupKey_FromMasterKey(masterKey: Buffer, aci: Buffer): MessageBackupKey;
export function MessageBackupKey_GetAesKey(key: Wrapper<MessageBackupKey>): Buffer;
export function MessageBackupKey_GetHmacKey(key: Wrapper<MessageBackupKey>): Buffer;
export function MessageBackupValidator_Validate(key: Wrapper<MessageBackupKey>, firstStream: InputStream, secondStream: InputStream, len: bigint, purpose: number): Promise<MessageBackupValidationOutcome>;
export function MinidumpToJSONString(buffer: Buffer): string;
export function Mp4Sanitizer_Sanitize(input: InputStream, len: bigint): Promise<SanitizedMetadata>;
export function OnlineBackupValidator_AddFrame(backup: Wrapper<OnlineBackupValidator>, frame: Buffer): void;
export function OnlineBackupValidator_Finalize(backup: Wrapper<OnlineBackupValidator>): void;
export function OnlineBackupValidator_New(backupInfoFrame: Buffer, purpose: number): OnlineBackupValidator;
export function PlaintextContent_Deserialize(data: Buffer): PlaintextContent;
export function PlaintextContent_FromDecryptionErrorMessage(m: Wrapper<DecryptionErrorMessage>): PlaintextContent;
export function PlaintextContent_GetBody(obj: Wrapper<PlaintextContent>): Buffer;
export function PlaintextContent_Serialize(obj: Wrapper<PlaintextContent>): Buffer;
export function PreKeyBundle_GetDeviceId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetIdentityKey(p: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetKyberPreKeyId(obj: Wrapper<PreKeyBundle>): number | null;
export function PreKeyBundle_GetKyberPreKeyPublic(bundle: Wrapper<PreKeyBundle>): KyberPublicKey | null;
export function PreKeyBundle_GetKyberPreKeySignature(bundle: Wrapper<PreKeyBundle>): Buffer;
export function PreKeyBundle_GetPreKeyId(obj: Wrapper<PreKeyBundle>): number | null;
export function PreKeyBundle_GetPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey | null;
export function PreKeyBundle_GetRegistrationId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetSignedPreKeySignature(obj: Wrapper<PreKeyBundle>): Buffer;
export function PreKeyBundle_New(registrationId: number, deviceId: number, prekeyId: number | null, prekey: Wrapper<PublicKey> | null, signedPrekeyId: number, signedPrekey: Wrapper<PublicKey>, signedPrekeySignature: Buffer, identityKey: Wrapper<PublicKey>, kyberPrekeyId: number | null, kyberPrekey: Wrapper<KyberPublicKey> | null, kyberPrekeySignature: Buffer): PreKeyBundle;
export function PreKeyRecord_Deserialize(data: Buffer): PreKeyRecord;
export function PreKeyRecord_GetId(obj: Wrapper<PreKeyRecord>): number;
export function PreKeyRecord_GetPrivateKey(obj: Wrapper<PreKeyRecord>): PrivateKey;
export function PreKeyRecord_GetPublicKey(obj: Wrapper<PreKeyRecord>): PublicKey;
export function PreKeyRecord_New(id: number, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>): PreKeyRecord;
export function PreKeyRecord_Serialize(obj: Wrapper<PreKeyRecord>): Buffer;
export function PreKeySignalMessage_Deserialize(data: Buffer): PreKeySignalMessage;
export function PreKeySignalMessage_GetPreKeyId(obj: Wrapper<PreKeySignalMessage>): number | null;
export function PreKeySignalMessage_GetRegistrationId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetSignedPreKeyId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetVersion(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_New(messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: Wrapper<PublicKey>, identityKey: Wrapper<PublicKey>, signalMessage: Wrapper<SignalMessage>): PreKeySignalMessage;
export function PreKeySignalMessage_Serialize(obj: Wrapper<PreKeySignalMessage>): Buffer;
export function PrivateKey_Agree(privateKey: Wrapper<PrivateKey>, publicKey: Wrapper<PublicKey>): Buffer;
export function PrivateKey_Deserialize(data: Buffer): PrivateKey;
export function PrivateKey_Generate(): PrivateKey;
export function PrivateKey_GetPublicKey(k: Wrapper<PrivateKey>): PublicKey;
export function PrivateKey_Serialize(obj: Wrapper<PrivateKey>): Buffer;
export function PrivateKey_Sign(key: Wrapper<PrivateKey>, message: Buffer): Buffer;
export function ProfileKeyCiphertext_CheckValidContents(buffer: Buffer): void;
export function ProfileKeyCommitment_CheckValidContents(buffer: Buffer): void;
export function ProfileKeyCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(presentationBytes: Buffer): Serialized<ProfileKeyCiphertext>;
export function ProfileKeyCredentialPresentation_GetUuidCiphertext(presentationBytes: Buffer): Serialized<UuidCiphertext>;
export function ProfileKeyCredentialRequestContext_CheckValidContents(buffer: Buffer): void;
export function ProfileKeyCredentialRequestContext_GetRequest(context: Serialized<ProfileKeyCredentialRequestContext>): Serialized<ProfileKeyCredentialRequest>;
export function ProfileKeyCredentialRequest_CheckValidContents(buffer: Buffer): void;
export function ProfileKey_CheckValidContents(buffer: Buffer): void;
export function ProfileKey_DeriveAccessKey(profileKey: Serialized<ProfileKey>): Buffer;
export function ProfileKey_GetCommitment(profileKey: Serialized<ProfileKey>, userId: Buffer): Serialized<ProfileKeyCommitment>;
export function ProfileKey_GetProfileKeyVersion(profileKey: Serialized<ProfileKey>, userId: Buffer): Buffer;
export function ProtocolAddress_DeviceId(obj: Wrapper<ProtocolAddress>): number;
export function ProtocolAddress_Name(obj: Wrapper<ProtocolAddress>): string;
export function ProtocolAddress_New(name: string, deviceId: number): ProtocolAddress;
export function PublicKey_Compare(key1: Wrapper<PublicKey>, key2: Wrapper<PublicKey>): number;
export function PublicKey_Deserialize(data: Buffer): PublicKey;
export function PublicKey_Equals(lhs: Wrapper<PublicKey>, rhs: Wrapper<PublicKey>): boolean;
export function PublicKey_GetPublicKeyBytes(obj: Wrapper<PublicKey>): Buffer;
export function PublicKey_Serialize(obj: Wrapper<PublicKey>): Buffer;
export function PublicKey_Verify(key: Wrapper<PublicKey>, message: Buffer, signature: Buffer): boolean;
export function ReceiptCredentialPresentation_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredentialPresentation_GetReceiptExpirationTime(presentation: Serialized<ReceiptCredentialPresentation>): Timestamp;
export function ReceiptCredentialPresentation_GetReceiptLevel(presentation: Serialized<ReceiptCredentialPresentation>): bigint;
export function ReceiptCredentialPresentation_GetReceiptSerial(presentation: Serialized<ReceiptCredentialPresentation>): Buffer;
export function ReceiptCredentialRequestContext_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredentialRequestContext_GetRequest(requestContext: Serialized<ReceiptCredentialRequestContext>): Serialized<ReceiptCredentialRequest>;
export function ReceiptCredentialRequest_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredentialResponse_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredential_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredential_GetReceiptExpirationTime(receiptCredential: Serialized<ReceiptCredential>): Timestamp;
export function ReceiptCredential_GetReceiptLevel(receiptCredential: Serialized<ReceiptCredential>): bigint;
export function SanitizedMetadata_GetDataLen(sanitized: Wrapper<SanitizedMetadata>): bigint;
export function SanitizedMetadata_GetDataOffset(sanitized: Wrapper<SanitizedMetadata>): bigint;
export function SanitizedMetadata_GetMetadata(sanitized: Wrapper<SanitizedMetadata>): Buffer;
export function ScannableFingerprint_Compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SealedSenderDecryptionResult_GetDeviceId(obj: Wrapper<SealedSenderDecryptionResult>): number;
export function SealedSenderDecryptionResult_GetSenderE164(obj: Wrapper<SealedSenderDecryptionResult>): string | null;
export function SealedSenderDecryptionResult_GetSenderUuid(obj: Wrapper<SealedSenderDecryptionResult>): string;
export function SealedSenderDecryptionResult_Message(obj: Wrapper<SealedSenderDecryptionResult>): Buffer;
export function SealedSenderMultiRecipientMessage_Parse(buffer: Buffer): SealedSenderMultiRecipientMessage;
export function SealedSender_DecryptMessage(message: Buffer, trustRoot: Wrapper<PublicKey>, timestamp: Timestamp, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore): Promise<SealedSenderDecryptionResult>;
export function SealedSender_DecryptToUsmc(ctext: Buffer, identityStore: IdentityKeyStore): Promise<UnidentifiedSenderMessageContent>;
export function SealedSender_Encrypt(destination: Wrapper<ProtocolAddress>, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore): Promise<Buffer>;
export function SealedSender_MultiRecipientEncrypt(recipients: Wrapper<ProtocolAddress>[], recipientSessions: Wrapper<SessionRecord>[], excludedRecipients: Buffer, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore): Promise<Buffer>;
export function SealedSender_MultiRecipientMessageForSingleRecipient(encodedMultiRecipientMessage: Buffer): Buffer;
export function SenderCertificate_Deserialize(data: Buffer): SenderCertificate;
export function SenderCertificate_GetCertificate(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_GetDeviceId(obj: Wrapper<SenderCertificate>): number;
export function SenderCertificate_GetExpiration(obj: Wrapper<SenderCertificate>): Timestamp;
export function SenderCertificate_GetKey(obj: Wrapper<SenderCertificate>): PublicKey;
export function SenderCertificate_GetSenderE164(obj: Wrapper<SenderCertificate>): string | null;
export function SenderCertificate_GetSenderUuid(obj: Wrapper<SenderCertificate>): string;
export function SenderCertificate_GetSerialized(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_GetServerCertificate(cert: Wrapper<SenderCertificate>): ServerCertificate;
export function SenderCertificate_GetSignature(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_New(senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: Wrapper<PublicKey>, expiration: Timestamp, signerCert: Wrapper<ServerCertificate>, signerKey: Wrapper<PrivateKey>): SenderCertificate;
export function SenderCertificate_Validate(cert: Wrapper<SenderCertificate>, key: Wrapper<PublicKey>, time: Timestamp): boolean;
export function SenderKeyDistributionMessage_Create(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, store: SenderKeyStore): Promise<SenderKeyDistributionMessage>;
export function SenderKeyDistributionMessage_Deserialize(data: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainId(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_GetChainKey(obj: Wrapper<SenderKeyDistributionMessage>): Buffer;
export function SenderKeyDistributionMessage_GetDistributionId(obj: Wrapper<SenderKeyDistributionMessage>): Uuid;
export function SenderKeyDistributionMessage_GetIteration(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, chainkey: Buffer, pk: Wrapper<PublicKey>): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Process(sender: Wrapper<ProtocolAddress>, senderKeyDistributionMessage: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore): Promise<void>;
export function SenderKeyDistributionMessage_Serialize(obj: Wrapper<SenderKeyDistributionMessage>): Buffer;
export function SenderKeyMessage_Deserialize(data: Buffer): SenderKeyMessage;
export function SenderKeyMessage_GetChainId(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_GetCipherText(obj: Wrapper<SenderKeyMessage>): Buffer;
export function SenderKeyMessage_GetDistributionId(obj: Wrapper<SenderKeyMessage>): Uuid;
export function SenderKeyMessage_GetIteration(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, ciphertext: Buffer, pk: Wrapper<PrivateKey>): SenderKeyMessage;
export function SenderKeyMessage_Serialize(obj: Wrapper<SenderKeyMessage>): Buffer;
export function SenderKeyMessage_VerifySignature(skm: Wrapper<SenderKeyMessage>, pubkey: Wrapper<PublicKey>): boolean;
export function SenderKeyRecord_Deserialize(data: Buffer): SenderKeyRecord;
export function SenderKeyRecord_Serialize(obj: Wrapper<SenderKeyRecord>): Buffer;
export function ServerCertificate_Deserialize(data: Buffer): ServerCertificate;
export function ServerCertificate_GetCertificate(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_GetKey(obj: Wrapper<ServerCertificate>): PublicKey;
export function ServerCertificate_GetKeyId(obj: Wrapper<ServerCertificate>): number;
export function ServerCertificate_GetSerialized(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_GetSignature(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_New(keyId: number, serverKey: Wrapper<PublicKey>, trustRoot: Wrapper<PrivateKey>): ServerCertificate;
export function ServerMessageAck_SendStatus(ack: Wrapper<ServerMessageAck>, status: number): void;
export function ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Buffer, groupSecretParams: Serialized<GroupSecretParams>, authCredentialWithPniBytes: Buffer): Buffer;
export function ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Buffer, groupSecretParams: Serialized<GroupSecretParams>, profileKeyCredential: Serialized<ExpiringProfileKeyCredential>): Buffer;
export function ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Buffer, userId: Buffer, profileKey: Serialized<ProfileKey>): Serialized<ProfileKeyCredentialRequestContext>;
export function ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Buffer, receiptCredential: Serialized<ReceiptCredential>): Serialized<ReceiptCredentialPresentation>;
export function ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(serverPublicParams: Wrapper<ServerPublicParams>, randomness: Buffer, receiptSerial: Buffer): Serialized<ReceiptCredentialRequestContext>;
export function ServerPublicParams_Deserialize(buffer: Buffer): ServerPublicParams;
export function ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(params: Wrapper<ServerPublicParams>, aci: Buffer, pni: Buffer, redemptionTime: Timestamp, authCredentialWithPniResponseBytes: Buffer): Buffer;
export function ServerPublicParams_ReceiveExpiringProfileKeyCredential(serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ProfileKeyCredentialRequestContext>, response: Serialized<ExpiringProfileKeyCredentialResponse>, currentTimeInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredential>;
export function ServerPublicParams_ReceiveReceiptCredential(serverPublicParams: Wrapper<ServerPublicParams>, requestContext: Serialized<ReceiptCredentialRequestContext>, response: Serialized<ReceiptCredentialResponse>): Serialized<ReceiptCredential>;
export function ServerPublicParams_Serialize(handle: Wrapper<ServerPublicParams>): Buffer;
export function ServerPublicParams_VerifySignature(serverPublicParams: Wrapper<ServerPublicParams>, message: Buffer, notarySignature: Buffer): void;
export function ServerSecretParams_Deserialize(buffer: Buffer): ServerSecretParams;
export function ServerSecretParams_GenerateDeterministic(randomness: Buffer): ServerSecretParams;
export function ServerSecretParams_GetPublicParams(params: Wrapper<ServerSecretParams>): ServerPublicParams;
export function ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Buffer, aci: Buffer, pni: Buffer, redemptionTime: Timestamp): Buffer;
export function ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Buffer, request: Serialized<ProfileKeyCredentialRequest>, userId: Buffer, commitment: Serialized<ProfileKeyCommitment>, expirationInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredentialResponse>;
export function ServerSecretParams_IssueReceiptCredentialDeterministic(serverSecretParams: Wrapper<ServerSecretParams>, randomness: Buffer, request: Serialized<ReceiptCredentialRequest>, receiptExpirationTime: Timestamp, receiptLevel: bigint): Serialized<ReceiptCredentialResponse>;
export function ServerSecretParams_Serialize(handle: Wrapper<ServerSecretParams>): Buffer;
export function ServerSecretParams_SignDeterministic(params: Wrapper<ServerSecretParams>, randomness: Buffer, message: Buffer): Buffer;
export function ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Buffer, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Buffer, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyReceiptCredentialPresentation(serverSecretParams: Wrapper<ServerSecretParams>, presentation: Serialized<ReceiptCredentialPresentation>): void;
export function ServiceId_ParseFromServiceIdBinary(input: Buffer): Buffer;
export function ServiceId_ParseFromServiceIdString(input: string): Buffer;
export function ServiceId_ServiceIdBinary(value: Buffer): Buffer;
export function ServiceId_ServiceIdLog(value: Buffer): string;
export function ServiceId_ServiceIdString(value: Buffer): string;
export function SessionBuilder_ProcessPreKeyBundle(bundle: Wrapper<PreKeyBundle>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp): Promise<void>;
export function SessionCipher_DecryptPreKeySignalMessage(message: Wrapper<PreKeySignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore): Promise<Buffer>;
export function SessionCipher_DecryptSignalMessage(message: Wrapper<SignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore): Promise<Buffer>;
export function SessionCipher_EncryptMessage(ptext: Buffer, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Timestamp): Promise<CiphertextMessage>;
export function SessionRecord_ArchiveCurrentState(sessionRecord: Wrapper<SessionRecord>): void;
export function SessionRecord_CurrentRatchetKeyMatches(s: Wrapper<SessionRecord>, key: Wrapper<PublicKey>): boolean;
export function SessionRecord_Deserialize(data: Buffer): SessionRecord;
export function SessionRecord_GetLocalRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_GetRemoteRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_HasUsableSenderChain(s: Wrapper<SessionRecord>, now: Timestamp): boolean;
export function SessionRecord_Serialize(obj: Wrapper<SessionRecord>): Buffer;
export function SgxClientState_CompleteHandshake(cli: Wrapper<SgxClientState>, handshakeReceived: Buffer): void;
export function SgxClientState_EstablishedRecv(cli: Wrapper<SgxClientState>, receivedCiphertext: Buffer): Buffer;
export function SgxClientState_EstablishedSend(cli: Wrapper<SgxClientState>, plaintextToSend: Buffer): Buffer;
export function SgxClientState_InitialRequest(obj: Wrapper<SgxClientState>): Buffer;
export function SignalMedia_CheckAvailable(): void;
export function SignalMessage_Deserialize(data: Buffer): SignalMessage;
export function SignalMessage_GetBody(obj: Wrapper<SignalMessage>): Buffer;
export function SignalMessage_GetCounter(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetMessageVersion(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetSerialized(obj: Wrapper<SignalMessage>): Buffer;
export function SignalMessage_New(messageVersion: number, macKey: Buffer, senderRatchetKey: Wrapper<PublicKey>, counter: number, previousCounter: number, ciphertext: Buffer, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>): SignalMessage;
export function SignalMessage_VerifyMac(msg: Wrapper<SignalMessage>, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, macKey: Buffer): boolean;
export function SignedPreKeyRecord_Deserialize(data: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_GetId(obj: Wrapper<SignedPreKeyRecord>): number;
export function SignedPreKeyRecord_GetPrivateKey(obj: Wrapper<SignedPreKeyRecord>): PrivateKey;
export function SignedPreKeyRecord_GetPublicKey(obj: Wrapper<SignedPreKeyRecord>): PublicKey;
export function SignedPreKeyRecord_GetSignature(obj: Wrapper<SignedPreKeyRecord>): Buffer;
export function SignedPreKeyRecord_GetTimestamp(obj: Wrapper<SignedPreKeyRecord>): Timestamp;
export function SignedPreKeyRecord_New(id: number, timestamp: Timestamp, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>, signature: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_Serialize(obj: Wrapper<SignedPreKeyRecord>): Buffer;
export function TESTING_CdsiLookupErrorConvert(errorDescription: string): void;
export function TESTING_CdsiLookupResponseConvert(asyncRuntime: Wrapper<TokioAsyncContext>): CancellablePromise<LookupResponse>;
export function TESTING_ChatRequestGetBody(request: Wrapper<HttpRequest>): Buffer;
export function TESTING_ChatRequestGetHeaderValue(request: Wrapper<HttpRequest>, headerName: string): string;
export function TESTING_ChatRequestGetMethod(request: Wrapper<HttpRequest>): string;
export function TESTING_ChatRequestGetPath(request: Wrapper<HttpRequest>): string;
export function TESTING_ChatResponseConvert(bodyPresent: boolean): ChatResponse;
export function TESTING_ChatServiceErrorConvert(errorDescription: string): void;
export function TESTING_ConnectionManager_isUsingProxy(manager: Wrapper<ConnectionManager>): number;
export function TESTING_ConnectionManager_newLocalOverride(userAgent: string, chatPort: number, cdsiPort: number, svr2Port: number, svr3SgxPort: number, svr3NitroPort: number, svr3Tpm2SnpPort: number, rootCertificateDer: Buffer): ConnectionManager;
export function TESTING_ErrorOnBorrowAsync(_input: null): Promise<void>;
export function TESTING_ErrorOnBorrowIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: null): CancellablePromise<void>;
export function TESTING_ErrorOnBorrowSync(_input: null): void;
export function TESTING_ErrorOnReturnAsync(_needsCleanup: null): Promise<null>;
export function TESTING_ErrorOnReturnIo(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _needsCleanup: null): CancellablePromise<null>;
export function TESTING_ErrorOnReturnSync(_needsCleanup: null): null;
export function TESTING_FakeChatConnection_Create(tokio: Wrapper<TokioAsyncContext>, listener: ChatListener): FakeChatConnection;
export function TESTING_FakeChatConnection_TakeAuthenticatedChat(chat: Wrapper<FakeChatConnection>): AuthenticatedChatConnection;
export function TESTING_FakeChatConnection_TakeRemote(chat: Wrapper<FakeChatConnection>): FakeChatRemoteEnd;
export function TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(chat: Wrapper<FakeChatRemoteEnd>): void;
export function TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<FakeChatRemoteEnd>): CancellablePromise<FakeChatSentRequest | null>;
export function TESTING_FakeChatRemoteEnd_SendRawServerRequest(chat: Wrapper<FakeChatRemoteEnd>, bytes: Buffer): void;
export function TESTING_FakeChatRemoteEnd_SendRawServerResponse(chat: Wrapper<FakeChatRemoteEnd>, bytes: Buffer): void;
export function TESTING_FakeChatSentRequest_RequestId(request: Wrapper<FakeChatSentRequest>): bigint;
export function TESTING_FakeChatSentRequest_TakeHttpRequest(request: Wrapper<FakeChatSentRequest>): HttpRequest;
export function TESTING_FutureFailure(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, _input: number): CancellablePromise<number>;
export function TESTING_FutureProducesOtherPointerType(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: string): CancellablePromise<OtherTestingHandleType>;
export function TESTING_FutureProducesPointerType(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number): CancellablePromise<TestingHandleType>;
export function TESTING_FutureSuccess(asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>, input: number): CancellablePromise<number>;
export function TESTING_InputStreamReadIntoZeroLengthSlice(capsAlphabetInput: InputStream): Promise<Buffer>;
export function TESTING_NonSuspendingBackgroundThreadRuntime_New(): NonSuspendingBackgroundThreadRuntime;
export function TESTING_OnlyCompletesByCancellation(asyncRuntime: Wrapper<TokioAsyncContext>): CancellablePromise<void>;
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
export function TESTING_ProcessBytestringArray(input: Buffer[]): Buffer[];
export function TESTING_ReturnStringArray(): string[];
export function TESTING_RoundTripI32(input: number): number;
export function TESTING_RoundTripU16(input: number): number;
export function TESTING_RoundTripU32(input: number): number;
export function TESTING_RoundTripU64(input: bigint): bigint;
export function TESTING_RoundTripU8(input: number): number;
export function TESTING_ServerMessageAck_Create(): ServerMessageAck;
export function TESTING_TestingHandleType_getValue(handle: Wrapper<TestingHandleType>): number;
export function TokioAsyncContext_cancel(context: Wrapper<TokioAsyncContext>, rawCancellationId: bigint): void;
export function TokioAsyncContext_new(): TokioAsyncContext;
export function UnauthenticatedChatConnection_connect(asyncRuntime: Wrapper<TokioAsyncContext>, connectionManager: Wrapper<ConnectionManager>): CancellablePromise<UnauthenticatedChatConnection>;
export function UnauthenticatedChatConnection_disconnect(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>): CancellablePromise<void>;
export function UnauthenticatedChatConnection_info(chat: Wrapper<UnauthenticatedChatConnection>): ChatConnectionInfo;
export function UnauthenticatedChatConnection_init_listener(chat: Wrapper<UnauthenticatedChatConnection>, listener: ChatListener): void;
export function UnauthenticatedChatConnection_send(asyncRuntime: Wrapper<TokioAsyncContext>, chat: Wrapper<UnauthenticatedChatConnection>, httpRequest: Wrapper<HttpRequest>, timeoutMillis: number): CancellablePromise<ChatResponse>;
export function UnidentifiedSenderMessageContent_Deserialize(data: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContentHint(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetContents(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UnidentifiedSenderMessageContent_GetGroupId(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer | null;
export function UnidentifiedSenderMessageContent_GetMsgType(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetSenderCert(m: Wrapper<UnidentifiedSenderMessageContent>): SenderCertificate;
export function UnidentifiedSenderMessageContent_New(message: Wrapper<CiphertextMessage>, sender: Wrapper<SenderCertificate>, contentHint: number, groupId: Buffer | null): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_Serialize(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UsernameLink_Create(username: string, entropy: Buffer | null): Buffer;
export function UsernameLink_DecryptUsername(entropy: Buffer, encryptedUsername: Buffer): string;
export function Username_CandidatesFrom(nickname: string, minLen: number, maxLen: number): string[];
export function Username_Hash(username: string): Buffer;
export function Username_HashFromParts(nickname: string, discriminator: string, minLen: number, maxLen: number): Buffer;
export function Username_Proof(username: string, randomness: Buffer): Buffer;
export function Username_Verify(proof: Buffer, hash: Buffer): void;
export function UuidCiphertext_CheckValidContents(buffer: Buffer): void;
export function ValidatingMac_Finalize(mac: Wrapper<ValidatingMac>): number;
export function ValidatingMac_Initialize(key: Buffer, chunkSize: number, digests: Buffer): ValidatingMac;
export function ValidatingMac_Update(mac: Wrapper<ValidatingMac>, bytes: Buffer, offset: number, length: number): number;
export function WebpSanitizer_Sanitize(input: SyncInputStream): void;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
export function test_only_fn_returns_123(): number;
interface Aes256GcmSiv { readonly __type: unique symbol; }
interface AuthenticatedChatConnection { readonly __type: unique symbol; }
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
interface FakeChatSentRequest { readonly __type: unique symbol; }
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
interface TestingHandleType { readonly __type: unique symbol; }
interface TokioAsyncContext { readonly __type: unique symbol; }
interface UnauthenticatedChatConnection { readonly __type: unique symbol; }
interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
interface UuidCiphertext { readonly __type: unique symbol; }
interface ValidatingMac { readonly __type: unique symbol; }
