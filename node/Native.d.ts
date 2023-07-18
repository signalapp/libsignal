//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

type Uuid = Buffer;

/// A Native.Timestamp may be measured in seconds or in milliseconds;
/// what's important is that it's an integer less than Number.MAX_SAFE_INTEGER.
type Timestamp = number;

export abstract class IdentityKeyStore {
  _getIdentityKey(): Promise<PrivateKey>;
  _getLocalRegistrationId(): Promise<number>;
  _saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<boolean>;
  _isTrustedIdentity(name: ProtocolAddress, key: PublicKey, sending: boolean): Promise<boolean>;
  _getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class SessionStore {
  _saveSession(addr: ProtocolAddress, record: SessionRecord): Promise<void>;
  _getSession(addr: ProtocolAddress): Promise<SessionRecord | null>;
}

export abstract class PreKeyStore {
  _savePreKey(preKeyId: number, record: PreKeyRecord): Promise<void>;
  _getPreKey(preKeyId: number): Promise<PreKeyRecord>;
  _removePreKey(preKeyId: number): Promise<void>;
}

export abstract class SignedPreKeyStore {
  _saveSignedPreKey(signedPreKeyId: number, record: SignedPreKeyRecord): Promise<void>;
  _getSignedPreKey(signedPreKeyId: number): Promise<SignedPreKeyRecord>;
}

export abstract class KyberPreKeyStore {
  _saveKyberPreKey(kyberPreKeyId: number, record: KyberPreKeyRecord): Promise<void>;
  _getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;
  _markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void>;
}

export abstract class SenderKeyStore {
  _saveSenderKey(sender: ProtocolAddress, distributionId: Uuid, record: SenderKeyRecord): Promise<void>;
  _getSenderKey(sender: ProtocolAddress, distributionId: Uuid): Promise<SenderKeyRecord | null>;
}

export abstract class InputStream {
  _read(amount: number): Promise<Buffer>;
  _skip(amount: number): Promise<void>;
}

interface Wrapper<T> {
  readonly _nativeHandle: T
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type Serialized<T> = Buffer;

export function registerErrors(errorsModule: Record<string, unknown>): void;

export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
export function Aes256GcmSiv_Decrypt(aesGcmSiv: Wrapper<Aes256GcmSiv>, ctext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_Encrypt(aesGcmSivObj: Wrapper<Aes256GcmSiv>, ptext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_New(key: Buffer): Aes256GcmSiv;
export function AuthCredentialPresentation_CheckValidContents(presentationBytes: Buffer): void;
export function AuthCredentialPresentation_GetPniCiphertext(presentationBytes: Buffer): Buffer | null;
export function AuthCredentialPresentation_GetRedemptionTime(presentationBytes: Buffer): Timestamp;
export function AuthCredentialPresentation_GetUuidCiphertext(presentationBytes: Buffer): Serialized<UuidCiphertext>;
export function AuthCredentialResponse_CheckValidContents(buffer: Buffer): void;
export function AuthCredentialWithPniResponse_CheckValidContents(buffer: Buffer): void;
export function AuthCredentialWithPni_CheckValidContents(buffer: Buffer): void;
export function AuthCredential_CheckValidContents(buffer: Buffer): void;
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
export function CiphertextMessage_FromPlaintextContent(m: Wrapper<PlaintextContent>): CiphertextMessage;
export function CiphertextMessage_Serialize(obj: Wrapper<CiphertextMessage>): Buffer;
export function CiphertextMessage_Type(msg: Wrapper<CiphertextMessage>): number;
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
export function GroupCipher_DecryptMessage(sender: Wrapper<ProtocolAddress>, message: Buffer, store: SenderKeyStore, ctx: null): Promise<Buffer>;
export function GroupCipher_EncryptMessage(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, message: Buffer, store: SenderKeyStore, ctx: null): Promise<CiphertextMessage>;
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
export function HKDF_DeriveSecrets(outputLength: number, ikm: Buffer, label: Buffer | null, salt: Buffer | null): Buffer;
export function HsmEnclaveClient_CompleteHandshake(cli: Wrapper<HsmEnclaveClient>, handshakeReceived: Buffer): void;
export function HsmEnclaveClient_EstablishedRecv(cli: Wrapper<HsmEnclaveClient>, receivedCiphertext: Buffer): Buffer;
export function HsmEnclaveClient_EstablishedSend(cli: Wrapper<HsmEnclaveClient>, plaintextToSend: Buffer): Buffer;
export function HsmEnclaveClient_InitialRequest(obj: Wrapper<HsmEnclaveClient>): Buffer;
export function HsmEnclaveClient_New(trustedPublicKey: Buffer, trustedCodeHashes: Buffer): HsmEnclaveClient;
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
export function Mp4Sanitizer_Sanitize(input: InputStream, len: Buffer): Promise<SanitizedMetadata>;
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
export function ReceiptCredentialPresentation_GetReceiptLevel(presentation: Serialized<ReceiptCredentialPresentation>): Buffer;
export function ReceiptCredentialPresentation_GetReceiptSerial(presentation: Serialized<ReceiptCredentialPresentation>): Buffer;
export function ReceiptCredentialRequestContext_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredentialRequestContext_GetRequest(requestContext: Serialized<ReceiptCredentialRequestContext>): Serialized<ReceiptCredentialRequest>;
export function ReceiptCredentialRequest_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredentialResponse_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredential_CheckValidContents(buffer: Buffer): void;
export function ReceiptCredential_GetReceiptExpirationTime(receiptCredential: Serialized<ReceiptCredential>): Timestamp;
export function ReceiptCredential_GetReceiptLevel(receiptCredential: Serialized<ReceiptCredential>): Buffer;
export function SanitizedMetadata_GetDataLen(sanitized: Wrapper<SanitizedMetadata>): Buffer;
export function SanitizedMetadata_GetDataOffset(sanitized: Wrapper<SanitizedMetadata>): Buffer;
export function SanitizedMetadata_GetMetadata(sanitized: Wrapper<SanitizedMetadata>): Buffer;
export function ScannableFingerprint_Compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SealedSenderDecryptionResult_GetDeviceId(obj: Wrapper<SealedSenderDecryptionResult>): number;
export function SealedSenderDecryptionResult_GetSenderE164(obj: Wrapper<SealedSenderDecryptionResult>): string | null;
export function SealedSenderDecryptionResult_GetSenderUuid(obj: Wrapper<SealedSenderDecryptionResult>): string;
export function SealedSenderDecryptionResult_Message(obj: Wrapper<SealedSenderDecryptionResult>): Buffer;
export function SealedSender_DecryptMessage(message: Buffer, trustRoot: Wrapper<PublicKey>, timestamp: Timestamp, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore): Promise<SealedSenderDecryptionResult>;
export function SealedSender_DecryptToUsmc(ctext: Buffer, identityStore: IdentityKeyStore, ctx: null): Promise<UnidentifiedSenderMessageContent>;
export function SealedSender_Encrypt(destination: Wrapper<ProtocolAddress>, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
export function SealedSender_MultiRecipientEncrypt(recipients: Wrapper<ProtocolAddress>[], recipientSessions: Wrapper<SessionRecord>[], content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
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
export function SenderKeyDistributionMessage_Create(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, store: SenderKeyStore, ctx: null): Promise<SenderKeyDistributionMessage>;
export function SenderKeyDistributionMessage_Deserialize(data: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainId(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_GetChainKey(obj: Wrapper<SenderKeyDistributionMessage>): Buffer;
export function SenderKeyDistributionMessage_GetDistributionId(obj: Wrapper<SenderKeyDistributionMessage>): Uuid;
export function SenderKeyDistributionMessage_GetIteration(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, chainkey: Buffer, pk: Wrapper<PublicKey>): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Process(sender: Wrapper<ProtocolAddress>, senderKeyDistributionMessage: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore, ctx: null): Promise<void>;
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
export function ServerPublicParams_CheckValidContents(buffer: Buffer): void;
export function ServerPublicParams_CreateAuthCredentialPresentationDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, groupSecretParams: Serialized<GroupSecretParams>, authCredential: Serialized<AuthCredential>): Buffer;
export function ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, groupSecretParams: Serialized<GroupSecretParams>, authCredential: Serialized<AuthCredentialWithPni>): Buffer;
export function ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, groupSecretParams: Serialized<GroupSecretParams>, profileKeyCredential: Serialized<ExpiringProfileKeyCredential>): Buffer;
export function ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, userId: Buffer, profileKey: Serialized<ProfileKey>): Serialized<ProfileKeyCredentialRequestContext>;
export function ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, receiptCredential: Serialized<ReceiptCredential>): Serialized<ReceiptCredentialPresentation>;
export function ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(serverPublicParams: Serialized<ServerPublicParams>, randomness: Buffer, receiptSerial: Buffer): Serialized<ReceiptCredentialRequestContext>;
export function ServerPublicParams_ReceiveAuthCredential(params: Serialized<ServerPublicParams>, aci: Buffer, redemptionTime: number, response: Serialized<AuthCredentialResponse>): Serialized<AuthCredential>;
export function ServerPublicParams_ReceiveAuthCredentialWithPniAsAci(params: Serialized<ServerPublicParams>, aci: Buffer, pni: Buffer, redemptionTime: Timestamp, response: Serialized<AuthCredentialWithPniResponse>): Serialized<AuthCredentialWithPni>;
export function ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(params: Serialized<ServerPublicParams>, aci: Buffer, pni: Buffer, redemptionTime: Timestamp, response: Serialized<AuthCredentialWithPniResponse>): Serialized<AuthCredentialWithPni>;
export function ServerPublicParams_ReceiveExpiringProfileKeyCredential(serverPublicParams: Serialized<ServerPublicParams>, requestContext: Serialized<ProfileKeyCredentialRequestContext>, response: Serialized<ExpiringProfileKeyCredentialResponse>, currentTimeInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredential>;
export function ServerPublicParams_ReceiveReceiptCredential(serverPublicParams: Serialized<ServerPublicParams>, requestContext: Serialized<ReceiptCredentialRequestContext>, response: Serialized<ReceiptCredentialResponse>): Serialized<ReceiptCredential>;
export function ServerPublicParams_VerifySignature(serverPublicParams: Serialized<ServerPublicParams>, message: Buffer, notarySignature: Buffer): void;
export function ServerSecretParams_CheckValidContents(buffer: Buffer): void;
export function ServerSecretParams_GenerateDeterministic(randomness: Buffer): Serialized<ServerSecretParams>;
export function ServerSecretParams_GetPublicParams(params: Serialized<ServerSecretParams>): Serialized<ServerPublicParams>;
export function ServerSecretParams_IssueAuthCredentialDeterministic(serverSecretParams: Serialized<ServerSecretParams>, randomness: Buffer, aci: Buffer, redemptionTime: number): Serialized<AuthCredentialResponse>;
export function ServerSecretParams_IssueAuthCredentialWithPniAsAciDeterministic(serverSecretParams: Serialized<ServerSecretParams>, randomness: Buffer, aci: Buffer, pni: Buffer, redemptionTime: Timestamp): Serialized<AuthCredentialWithPniResponse>;
export function ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic(serverSecretParams: Serialized<ServerSecretParams>, randomness: Buffer, aci: Buffer, pni: Buffer, redemptionTime: Timestamp): Serialized<AuthCredentialWithPniResponse>;
export function ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams: Serialized<ServerSecretParams>, randomness: Buffer, request: Serialized<ProfileKeyCredentialRequest>, userId: Buffer, commitment: Serialized<ProfileKeyCommitment>, expirationInSeconds: Timestamp): Serialized<ExpiringProfileKeyCredentialResponse>;
export function ServerSecretParams_IssueReceiptCredentialDeterministic(serverSecretParams: Serialized<ServerSecretParams>, randomness: Buffer, request: Serialized<ReceiptCredentialRequest>, receiptExpirationTime: Timestamp, receiptLevel: Buffer): Serialized<ReceiptCredentialResponse>;
export function ServerSecretParams_SignDeterministic(params: Serialized<ServerSecretParams>, randomness: Buffer, message: Buffer): Buffer;
export function ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams: Serialized<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Buffer, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams: Serialized<ServerSecretParams>, groupPublicParams: Serialized<GroupPublicParams>, presentationBytes: Buffer, currentTimeInSeconds: Timestamp): void;
export function ServerSecretParams_VerifyReceiptCredentialPresentation(serverSecretParams: Serialized<ServerSecretParams>, presentation: Serialized<ReceiptCredentialPresentation>): void;
export function ServiceId_ParseFromServiceIdBinary(input: Buffer): Buffer;
export function ServiceId_ParseFromServiceIdString(input: string): Buffer;
export function ServiceId_ServiceIdBinary(value: Buffer): Buffer;
export function ServiceId_ServiceIdLog(value: Buffer): string;
export function ServiceId_ServiceIdString(value: Buffer): string;
export function SessionBuilder_ProcessPreKeyBundle(bundle: Wrapper<PreKeyBundle>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<void>;
export function SessionCipher_DecryptPreKeySignalMessage(message: Wrapper<PreKeySignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore, ctx: null): Promise<Buffer>;
export function SessionCipher_DecryptSignalMessage(message: Wrapper<SignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
export function SessionCipher_EncryptMessage(ptext: Buffer, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<CiphertextMessage>;
export function SessionRecord_ArchiveCurrentState(sessionRecord: Wrapper<SessionRecord>): void;
export function SessionRecord_CurrentRatchetKeyMatches(s: Wrapper<SessionRecord>, key: Wrapper<PublicKey>): boolean;
export function SessionRecord_Deserialize(data: Buffer): SessionRecord;
export function SessionRecord_GetLocalRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_GetRemoteRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_HasCurrentState(obj: Wrapper<SessionRecord>): boolean;
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
export function UnidentifiedSenderMessageContent_Deserialize(data: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContentHint(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetContents(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UnidentifiedSenderMessageContent_GetGroupId(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer | null;
export function UnidentifiedSenderMessageContent_GetMsgType(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetSenderCert(m: Wrapper<UnidentifiedSenderMessageContent>): SenderCertificate;
export function UnidentifiedSenderMessageContent_New(message: Wrapper<CiphertextMessage>, sender: Wrapper<SenderCertificate>, contentHint: number, groupId: Buffer | null): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_Serialize(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UsernameLink_Create(username: string): Buffer;
export function UsernameLink_DecryptUsername(entropy: Buffer, encryptedUsername: Buffer): string;
export function Username_CandidatesFrom(nickname: string, minLen: number, maxLen: number): string;
export function Username_Hash(username: string): Buffer;
export function Username_Proof(username: string, randomness: Buffer): Buffer;
export function Username_Verify(proof: Buffer, hash: Buffer): void;
export function UuidCiphertext_CheckValidContents(buffer: Buffer): void;
export function ValidatingMac_Finalize(mac: Wrapper<ValidatingMac>): boolean;
export function ValidatingMac_Initialize(key: Buffer, chunkSize: number, digests: Buffer): ValidatingMac;
export function ValidatingMac_Update(mac: Wrapper<ValidatingMac>, bytes: Buffer, offset: number, length: number): boolean;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
interface Aes256GcmSiv { readonly __type: unique symbol; }
interface AuthCredential { readonly __type: unique symbol; }
interface AuthCredentialResponse { readonly __type: unique symbol; }
interface AuthCredentialWithPni { readonly __type: unique symbol; }
interface AuthCredentialWithPniResponse { readonly __type: unique symbol; }
interface CiphertextMessage { readonly __type: unique symbol; }
interface DecryptionErrorMessage { readonly __type: unique symbol; }
interface ExpiringProfileKeyCredential { readonly __type: unique symbol; }
interface ExpiringProfileKeyCredentialResponse { readonly __type: unique symbol; }
interface Fingerprint { readonly __type: unique symbol; }
interface GroupMasterKey { readonly __type: unique symbol; }
interface GroupPublicParams { readonly __type: unique symbol; }
interface GroupSecretParams { readonly __type: unique symbol; }
interface HsmEnclaveClient { readonly __type: unique symbol; }
interface IncrementalMac { readonly __type: unique symbol; }
interface KyberKeyPair { readonly __type: unique symbol; }
interface KyberPreKeyRecord { readonly __type: unique symbol; }
interface KyberPublicKey { readonly __type: unique symbol; }
interface KyberSecretKey { readonly __type: unique symbol; }
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
interface ServerPublicParams { readonly __type: unique symbol; }
interface ServerSecretParams { readonly __type: unique symbol; }
interface SessionRecord { readonly __type: unique symbol; }
interface SgxClientState { readonly __type: unique symbol; }
interface SignalMessage { readonly __type: unique symbol; }
interface SignedPreKeyRecord { readonly __type: unique symbol; }
interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
interface UuidCiphertext { readonly __type: unique symbol; }
interface ValidatingMac { readonly __type: unique symbol; }
