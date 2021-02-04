//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

export const enum CiphertextMessageType { Whisper = 2, PreKey = 3, SenderKey = 4, SenderKeyDistribution = 5 }
export const enum LogLevel { Error, Warn, Info, Debug, Trace }
export function Aes256GcmSiv_Decrypt(aesGcmSiv: Aes256GcmSiv, ctext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_Encrypt(aesGcmSiv: Aes256GcmSiv, ptext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_New(key: Buffer): Aes256GcmSiv;
export function CiphertextMessage_Serialize(obj: CiphertextMessage): Buffer;
export function CiphertextMessage_Type(msg: CiphertextMessage): number;
export function Fingerprint_DisplayString(obj: Fingerprint): string;
export function Fingerprint_New(iterations: number, version: number, localIdentifier: Buffer, localKey: PublicKey, remoteIdentifier: Buffer, remoteKey: PublicKey): Fingerprint;
export function Fingerprint_ScannableEncoding(obj: Fingerprint): Buffer;
export function HKDF_DeriveSecrets(outputLength: number, version: number, ikm: Buffer, label: Buffer, salt: Buffer | null): Buffer;
export function IdentityKeyPair_Serialize(publicKey: PublicKey, privateKey: PrivateKey): Buffer;
export function PreKeyBundle_GetDeviceId(obj: PreKeyBundle): number;
export function PreKeyBundle_GetIdentityKey(p: PreKeyBundle): PublicKey;
export function PreKeyBundle_GetPreKeyId(obj: PreKeyBundle): number | null;
export function PreKeyBundle_GetPreKeyPublic(obj: PreKeyBundle): PublicKey | null;
export function PreKeyBundle_GetRegistrationId(obj: PreKeyBundle): number;
export function PreKeyBundle_GetSignedPreKeyId(obj: PreKeyBundle): number;
export function PreKeyBundle_GetSignedPreKeyPublic(obj: PreKeyBundle): PublicKey;
export function PreKeyBundle_GetSignedPreKeySignature(obj: PreKeyBundle): Buffer;
export function PreKeyBundle_New(registrationId: number, deviceId: number, prekeyId: number | null, prekey: PublicKey | null, signedPrekeyId: number, signedPrekey: PublicKey, signedPrekeySignature: Buffer, identityKey: PublicKey): PreKeyBundle;
export function PreKeyRecord_Deserialize(buffer: Buffer): PreKeyRecord;
export function PreKeyRecord_GetId(obj: PreKeyRecord): number;
export function PreKeyRecord_GetPrivateKey(obj: PreKeyRecord): PrivateKey;
export function PreKeyRecord_GetPublicKey(obj: PreKeyRecord): PublicKey;
export function PreKeyRecord_New(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord;
export function PreKeyRecord_Serialize(obj: PreKeyRecord): Buffer;
export function PreKeySignalMessage_Deserialize(buffer: Buffer): PreKeySignalMessage;
export function PreKeySignalMessage_GetPreKeyId(obj: PreKeySignalMessage): number | null;
export function PreKeySignalMessage_GetRegistrationId(obj: PreKeySignalMessage): number;
export function PreKeySignalMessage_GetSignedPreKeyId(obj: PreKeySignalMessage): number;
export function PreKeySignalMessage_GetVersion(obj: PreKeySignalMessage): number;
export function PreKeySignalMessage_New(messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: PublicKey, identityKey: PublicKey, signalMessage: SignalMessage): PreKeySignalMessage;
export function PreKeySignalMessage_Serialize(obj: PreKeySignalMessage): Buffer;
export function PrivateKey_Agree(privateKey: PrivateKey, publicKey: PublicKey): Buffer;
export function PrivateKey_Deserialize(buffer: Buffer): PrivateKey;
export function PrivateKey_Generate(): PrivateKey;
export function PrivateKey_GetPublicKey(k: PrivateKey): PublicKey;
export function PrivateKey_Serialize(obj: PrivateKey): Buffer;
export function PrivateKey_Sign(key: PrivateKey, message: Buffer): Buffer;
export function ProtocolAddress_DeviceId(obj: ProtocolAddress): number;
export function ProtocolAddress_Name(obj: ProtocolAddress): string;
export function ProtocolAddress_New(name: string, deviceId: number): ProtocolAddress;
export function PublicKey_Compare(key1: PublicKey, key2: PublicKey): number;
export function PublicKey_Deserialize(buffer: Buffer): PublicKey;
export function PublicKey_GetPublicKeyBytes(obj: PublicKey): Buffer;
export function PublicKey_Serialize(obj: PublicKey): Buffer;
export function PublicKey_Verify(key: PublicKey, message: Buffer, signature: Buffer): boolean;
export function ScannableFingerprint_Compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SenderCertificate_Deserialize(buffer: Buffer): SenderCertificate;
export function SenderCertificate_GetCertificate(obj: SenderCertificate): Buffer;
export function SenderCertificate_GetDeviceId(obj: SenderCertificate): number;
export function SenderCertificate_GetExpiration(obj: SenderCertificate): number;
export function SenderCertificate_GetKey(obj: SenderCertificate): PublicKey;
export function SenderCertificate_GetSenderE164(obj: SenderCertificate): string | null;
export function SenderCertificate_GetSenderUuid(obj: SenderCertificate): string | null;
export function SenderCertificate_GetSerialized(obj: SenderCertificate): Buffer;
export function SenderCertificate_GetServerCertificate(cert: SenderCertificate): ServerCertificate;
export function SenderCertificate_GetSignature(obj: SenderCertificate): Buffer;
export function SenderCertificate_New(senderUuid: string | null, senderE164: string | null, senderDeviceId: number, senderKey: PublicKey, expiration: number, signerCert: ServerCertificate, signerKey: PrivateKey): SenderCertificate;
export function SenderCertificate_Validate(cert: SenderCertificate, key: PublicKey, time: number): boolean;
export function SenderKeyDistributionMessage_Deserialize(buffer: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainKey(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_GetId(obj: SenderKeyDistributionMessage): number;
export function SenderKeyDistributionMessage_GetIteration(obj: SenderKeyDistributionMessage): number;
export function SenderKeyDistributionMessage_New(keyId: number, iteration: number, chainkey: Buffer, pk: PublicKey): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Serialize(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyMessage_Deserialize(buffer: Buffer): SenderKeyMessage;
export function SenderKeyMessage_GetCipherText(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_GetIteration(obj: SenderKeyMessage): number;
export function SenderKeyMessage_GetKeyId(obj: SenderKeyMessage): number;
export function SenderKeyMessage_New(keyId: number, iteration: number, ciphertext: Buffer, pk: PrivateKey): SenderKeyMessage;
export function SenderKeyMessage_Serialize(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_VerifySignature(skm: SenderKeyMessage, pubkey: PublicKey): boolean;
export function SenderKeyName_GetGroupId(obj: SenderKeyName): string;
export function SenderKeyName_GetSenderDeviceId(skn: SenderKeyName): number;
export function SenderKeyName_GetSenderName(obj: SenderKeyName): string;
export function SenderKeyName_New(groupId: string, senderName: string, senderDeviceId: number): SenderKeyName;
export function SenderKeyRecord_Deserialize(buffer: Buffer): SenderKeyRecord;
export function SenderKeyRecord_New(): SenderKeyRecord;
export function SenderKeyRecord_Serialize(obj: SenderKeyRecord): Buffer;
export function ServerCertificate_Deserialize(buffer: Buffer): ServerCertificate;
export function ServerCertificate_GetCertificate(obj: ServerCertificate): Buffer;
export function ServerCertificate_GetKey(obj: ServerCertificate): PublicKey;
export function ServerCertificate_GetKeyId(obj: ServerCertificate): number;
export function ServerCertificate_GetSerialized(obj: ServerCertificate): Buffer;
export function ServerCertificate_GetSignature(obj: ServerCertificate): Buffer;
export function ServerCertificate_New(keyId: number, serverKey: PublicKey, trustRoot: PrivateKey): ServerCertificate;
export function SessionRecord_ArchiveCurrentState(sessionRecord: SessionRecord): void;
export function SessionRecord_Deserialize(buffer: Buffer): SessionRecord;
export function SessionRecord_GetLocalRegistrationId(obj: SessionRecord): number;
export function SessionRecord_GetRemoteRegistrationId(obj: SessionRecord): number;
export function SessionRecord_Serialize(obj: SessionRecord): Buffer;
export function SignalMessage_Deserialize(buffer: Buffer): SignalMessage;
export function SignalMessage_GetBody(obj: SignalMessage): Buffer;
export function SignalMessage_GetCounter(obj: SignalMessage): number;
export function SignalMessage_GetMessageVersion(obj: SignalMessage): number;
export function SignalMessage_GetSerialized(obj: SignalMessage): Buffer;
export function SignalMessage_New(messageVersion: number, macKey: Buffer, senderRatchetKey: PublicKey, counter: number, previousCounter: number, ciphertext: Buffer, senderIdentityKey: PublicKey, receiverIdentityKey: PublicKey): SignalMessage;
export function SignalMessage_VerifyMac(msg: SignalMessage, senderIdentityKey: PublicKey, receiverIdentityKey: PublicKey, macKey: Buffer): boolean;
export function SignedPreKeyRecord_Deserialize(buffer: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_GetId(obj: SignedPreKeyRecord): number;
export function SignedPreKeyRecord_GetPrivateKey(obj: SignedPreKeyRecord): PrivateKey;
export function SignedPreKeyRecord_GetPublicKey(obj: SignedPreKeyRecord): PublicKey;
export function SignedPreKeyRecord_GetSignature(obj: SignedPreKeyRecord): Buffer;
export function SignedPreKeyRecord_GetTimestamp(obj: SignedPreKeyRecord): number;
export function SignedPreKeyRecord_New(id: number, timestamp: number, pubKey: PublicKey, privKey: PrivateKey, signature: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_Serialize(obj: SignedPreKeyRecord): Buffer;
export function UnidentifiedSenderMessageContent_Deserialize(buffer: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContents(obj: UnidentifiedSenderMessageContent): Buffer;
export function UnidentifiedSenderMessageContent_GetMsgType(m: UnidentifiedSenderMessageContent): number;
export function UnidentifiedSenderMessageContent_GetSenderCert(m: UnidentifiedSenderMessageContent): SenderCertificate;
export function UnidentifiedSenderMessageContent_Serialize(obj: UnidentifiedSenderMessageContent): Buffer;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
interface Aes256GcmSiv { readonly __type: unique symbol; }
interface CiphertextMessage { readonly __type: unique symbol; }
interface Fingerprint { readonly __type: unique symbol; }
interface PreKeyBundle { readonly __type: unique symbol; }
interface PreKeyRecord { readonly __type: unique symbol; }
interface PreKeySignalMessage { readonly __type: unique symbol; }
interface PrivateKey { readonly __type: unique symbol; }
interface ProtocolAddress { readonly __type: unique symbol; }
interface PublicKey { readonly __type: unique symbol; }
interface SenderCertificate { readonly __type: unique symbol; }
interface SenderKeyDistributionMessage { readonly __type: unique symbol; }
interface SenderKeyMessage { readonly __type: unique symbol; }
interface SenderKeyName { readonly __type: unique symbol; }
interface SenderKeyRecord { readonly __type: unique symbol; }
interface ServerCertificate { readonly __type: unique symbol; }
interface SessionRecord { readonly __type: unique symbol; }
interface SignalMessage { readonly __type: unique symbol; }
interface SignedPreKeyRecord { readonly __type: unique symbol; }
interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
