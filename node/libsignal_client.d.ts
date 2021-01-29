//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

export const enum LogLevel { Error, Warn, Info, Debug, Trace }
export function Aes256GcmSiv_Decrypt(aes_gcm_siv: Aes256GcmSiv, ctext: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
export function Aes256GcmSiv_Encrypt(aes_gcm_siv: Aes256GcmSiv, ptext: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
export function Aes256GcmSiv_New(key: Buffer): Aes256GcmSiv;
export function DisplayableFingerprint_Format(local: Buffer, remote: Buffer): string;
export function Fingerprint_DisplayString(obj: Fingerprint): string;
export function Fingerprint_ScannableEncoding(obj: Fingerprint): Buffer;
export function IdentityKeyPair_Serialize(public_key: PublicKey, private_key: PrivateKey): Buffer;
export function PreKeyBundle_GetSignedPreKeySignature(obj: PreKeyBundle): Buffer;
export function PreKeyRecord_Deserialize(buffer: Buffer): PreKeyRecord;
export function PreKeyRecord_New(id: number, pub_key: PublicKey, priv_key: PrivateKey): PreKeyRecord;
export function PreKeyRecord_Serialize(obj: PreKeyRecord): Buffer;
export function PreKeySignalMessage_Deserialize(buffer: Buffer): PreKeySignalMessage;
export function PreKeySignalMessage_GetBaseKey(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_GetIdentityKey(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_GetSignalMessage(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_New(message_version: number, registration_id: number, pre_key_id: number | null, signed_pre_key_id: number, base_key: PublicKey, identity_key: PublicKey, signal_message: SignalMessage): PreKeySignalMessage;
export function PreKeySignalMessage_Serialize(obj: PreKeySignalMessage): Buffer;
export function PrivateKey_Agree(private_key: PrivateKey, public_key: PublicKey): Buffer;
export function PrivateKey_Deserialize(buffer: Buffer): PrivateKey;
export function PrivateKey_Generate(): PrivateKey;
export function PrivateKey_GetPublicKey(k: PrivateKey): PublicKey;
export function PrivateKey_Serialize(obj: PrivateKey): Buffer;
export function PrivateKey_Sign(key: PrivateKey, message: Buffer): Buffer;
export function ProtocolAddress_Name(obj: ProtocolAddress): string;
export function ProtocolAddress_New(name: string, device_id: number): ProtocolAddress;
export function PublicKey_Compare(key1: PublicKey, key2: PublicKey): number;
export function PublicKey_Deserialize(buffer: Buffer): PublicKey;
export function PublicKey_GetPublicKeyBytes(obj: PublicKey): Buffer;
export function PublicKey_Serialize(obj: PublicKey): Buffer;
export function PublicKey_Verify(key: PublicKey, message: Buffer, signature: Buffer): boolean;
export function ScannableFingerprint_Compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SenderCertificate_Deserialize(buffer: Buffer): SenderCertificate;
export function SenderCertificate_GetCertificate(obj: SenderCertificate): Buffer;
export function SenderCertificate_GetSenderE164(obj: SenderCertificate): string | null;
export function SenderCertificate_GetSenderUuid(obj: SenderCertificate): string | null;
export function SenderCertificate_GetSerialized(obj: SenderCertificate): Buffer;
export function SenderCertificate_GetSignature(obj: SenderCertificate): Buffer;
export function SenderCertificate_New(sender_uuid: string | null, sender_e164: string | null, sender_device_id: number, sender_key: PublicKey, expiration: number, signer_cert: ServerCertificate, signer_key: PrivateKey): SenderCertificate;
export function SenderCertificate_Validate(cert: SenderCertificate, key: PublicKey, time: number): boolean;
export function SenderKeyDistributionMessage_Deserialize(buffer: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainKey(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_GetSignatureKey(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_New(key_id: number, iteration: number, chainkey: Buffer, pk: PublicKey): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Serialize(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyMessage_Deserialize(buffer: Buffer): SenderKeyMessage;
export function SenderKeyMessage_GetCipherText(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_New(key_id: number, iteration: number, ciphertext: Buffer, pk: PrivateKey): SenderKeyMessage;
export function SenderKeyMessage_Serialize(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_VerifySignature(skm: SenderKeyMessage, pubkey: PublicKey): boolean;
export function SenderKeyName_GetGroupId(obj: SenderKeyName): string;
export function SenderKeyName_GetSenderName(obj: SenderKeyName): string;
export function SenderKeyName_New(group_id: string, sender_name: string, sender_device_id: number): SenderKeyName;
export function SenderKeyRecord_Deserialize(buffer: Buffer): SenderKeyRecord;
export function SenderKeyRecord_New(): SenderKeyRecord;
export function SenderKeyRecord_Serialize(obj: SenderKeyRecord): Buffer;
export function ServerCertificate_Deserialize(buffer: Buffer): ServerCertificate;
export function ServerCertificate_GetCertificate(obj: ServerCertificate): Buffer;
export function ServerCertificate_GetSerialized(obj: ServerCertificate): Buffer;
export function ServerCertificate_GetSignature(obj: ServerCertificate): Buffer;
export function ServerCertificate_New(key_id: number, server_key: PublicKey, trust_root: PrivateKey): ServerCertificate;
export function SessionRecord_Deserialize(buffer: Buffer): SessionRecord;
export function SessionRecord_GetAliceBaseKey(obj: SessionRecord): Buffer;
export function SessionRecord_GetLocalIdentityKeyPublic(obj: SessionRecord): Buffer;
export function SessionRecord_GetRemoteIdentityKeyPublic(obj: SessionRecord): Buffer|null;
export function SessionRecord_GetSenderChainKeyValue(obj: SessionRecord): Buffer;
export function SessionRecord_Serialize(obj: SessionRecord): Buffer;
export function SignalMessage_Deserialize(buffer: Buffer): SignalMessage;
export function SignalMessage_GetBody(obj: SignalMessage): Buffer;
export function SignalMessage_GetSenderRatchetKey(obj: SignalMessage): Buffer;
export function SignalMessage_GetSerialized(obj: SignalMessage): Buffer;
export function SignalMessage_New(message_version: number, mac_key: Buffer, sender_ratchet_key: PublicKey, counter: number, previous_counter: number, ciphertext: Buffer, sender_identity_key: PublicKey, receiver_identity_key: PublicKey): SignalMessage;
export function SignalMessage_VerifyMac(msg: SignalMessage, sender_identity_key: PublicKey, receiver_identity_key: PublicKey, mac_key: Buffer): boolean;
export function SignedPreKeyRecord_Deserialize(buffer: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_GetSignature(obj: SignedPreKeyRecord): Buffer;
export function SignedPreKeyRecord_New(id: number, timestamp: number, pub_key: PublicKey, priv_key: PrivateKey, signature: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_Serialize(obj: SignedPreKeyRecord): Buffer;
export function UnidentifiedSenderMessageContent_Deserialize(buffer: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContents(obj: UnidentifiedSenderMessageContent): Buffer;
export function UnidentifiedSenderMessageContent_Serialize(obj: UnidentifiedSenderMessageContent): Buffer;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
interface Aes256GcmSiv { readonly __type: unique symbol; }
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
