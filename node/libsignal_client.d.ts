//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

export const enum LogLevel { Error, Warn, Info, Debug, Trace }
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
export function ProtocolAddress_name(obj: ProtocolAddress): string;
export function ProtocolAddress_new(name: string, device_id: number): ProtocolAddress;
export function PublicKey_deserialize(buffer: Buffer): PublicKey;
export function PublicKey_serialize(obj: PublicKey): Buffer;
export function PublicKey_get_public_key_bytes(obj: PublicKey): Buffer;
export function PublicKey_compare(key1: PublicKey, key2: PublicKey): number;
export function PublicKey_verify(key: PublicKey, message: Buffer, signature: Buffer): boolean;
export function PrivateKey_deserialize(buffer: Buffer): PrivateKey;
export function PrivateKey_serialize(obj: PrivateKey): Buffer;
export function PrivateKey_generate(): PrivateKey;
export function PrivateKey_getPublicKey(k: PrivateKey): PublicKey;
export function PrivateKey_sign(key: PrivateKey, message: Buffer): Buffer;
export function PrivateKey_agree(private_key: PrivateKey, public_key: PublicKey): Buffer;
export function IdentityKeyPair_serialize(public_key: PublicKey, private_key: PrivateKey): Buffer;
export function Fingerprint_scannable_encoding(obj: Fingerprint): Buffer;
export function Fingerprint_display_string(obj: Fingerprint): string;
export function DisplayableFingerprint_format(local: Buffer, remote: Buffer): string;
export function ScannableFingerprint_compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SignalMessage_deserialize(buffer: Buffer): SignalMessage;
export function SignalMessage_get_sender_ratchet_key(obj: SignalMessage): Buffer;
export function SignalMessage_get_body(obj: SignalMessage): Buffer;
export function SignalMessage_get_serialized(obj: SignalMessage): Buffer;
export function SignalMessage_new(message_version: number, mac_key: Buffer, sender_ratchet_key: PublicKey, counter: number, previous_counter: number, ciphertext: Buffer, sender_identity_key: PublicKey, receiver_identity_key: PublicKey): SignalMessage;
export function SignalMessage_verifyMac(msg: SignalMessage, sender_identity_key: PublicKey, receiver_identity_key: PublicKey, mac_key: Buffer): boolean;
export function PreKeySignalMessage_new(message_version: number, registration_id: number, pre_key_id: number | null, signed_pre_key_id: number, base_key: PublicKey, identity_key: PublicKey, signal_message: SignalMessage): PreKeySignalMessage;
export function PreKeySignalMessage_deserialize(buffer: Buffer): PreKeySignalMessage;
export function PreKeySignalMessage_serialize(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_get_base_key(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_get_identity_key(obj: PreKeySignalMessage): Buffer;
export function PreKeySignalMessage_get_signal_message(obj: PreKeySignalMessage): Buffer;
export function SenderKeyMessage_deserialize(buffer: Buffer): SenderKeyMessage;
export function SenderKeyMessage_get_cipher_text(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_serialize(obj: SenderKeyMessage): Buffer;
export function SenderKeyMessage_new(key_id: number, iteration: number, ciphertext: Buffer, pk: PrivateKey): SenderKeyMessage;
export function SenderKeyMessage_verifySignature(skm: SenderKeyMessage, pubkey: PublicKey): boolean;
export function SenderKeyDistributionMessage_deserialize(buffer: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_get_chain_key(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_get_signature_key(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_serialize(obj: SenderKeyDistributionMessage): Buffer;
export function SenderKeyDistributionMessage_new(key_id: number, iteration: number, chainkey: Buffer, pk: PublicKey): SenderKeyDistributionMessage;
export function PreKeyBundle_get_signed_pre_key_signature(obj: PreKeyBundle): Buffer;
export function SignedPreKeyRecord_deserialize(buffer: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_get_signature(obj: SignedPreKeyRecord): Buffer;
export function SignedPreKeyRecord_serialize(obj: SignedPreKeyRecord): Buffer;
export function SignedPreKeyRecord_new(id: number, timestamp: number, pub_key: PublicKey, priv_key: PrivateKey, signature: Buffer): SignedPreKeyRecord;
export function PreKeyRecord_deserialize(buffer: Buffer): PreKeyRecord;
export function PreKeyRecord_serialize(obj: PreKeyRecord): Buffer;
export function PreKeyRecord_new(id: number, pub_key: PublicKey, priv_key: PrivateKey): PreKeyRecord;
export function SenderKeyName_get_group_id(obj: SenderKeyName): string;
export function SenderKeyName_get_sender_name(obj: SenderKeyName): string;
export function SenderKeyName_new(group_id: string, sender_name: string, sender_device_id: number): SenderKeyName;
export function SenderKeyRecord_deserialize(buffer: Buffer): SenderKeyRecord;
export function SenderKeyRecord_serialize(obj: SenderKeyRecord): Buffer;
export function SenderKeyRecord_new(): SenderKeyRecord;
export function ServerCertificate_deserialize(buffer: Buffer): ServerCertificate;
export function ServerCertificate_get_serialized(obj: ServerCertificate): Buffer;
export function ServerCertificate_get_certificate(obj: ServerCertificate): Buffer;
export function ServerCertificate_get_signature(obj: ServerCertificate): Buffer;
export function ServerCertificate_new(key_id: number, server_key: PublicKey, trust_root: PrivateKey): ServerCertificate;
export function SenderCertificate_deserialize(buffer: Buffer): SenderCertificate;
export function SenderCertificate_get_serialized(obj: SenderCertificate): Buffer;
export function SenderCertificate_get_certificate(obj: SenderCertificate): Buffer;
export function SenderCertificate_get_signature(obj: SenderCertificate): Buffer;
export function SenderCertificate_get_sender_uuid(obj: SenderCertificate): string|null;
export function SenderCertificate_get_sender_e164(obj: SenderCertificate): string|null;
export function SenderCertificate_validate(cert: SenderCertificate, key: PublicKey, time: number): boolean;
export function SenderCertificate_new(sender_uuid: string | null, sender_e164: string | null, sender_device_id: number, sender_key: PublicKey, expiration: number, signer_cert: ServerCertificate, signer_key: PrivateKey): SenderCertificate;
export function UnidentifiedSenderMessageContent_deserialize(buffer: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_serialize(obj: UnidentifiedSenderMessageContent): Buffer;
export function UnidentifiedSenderMessageContent_get_contents(obj: UnidentifiedSenderMessageContent): Buffer;
export function SessionRecord_deserialize(buffer: Buffer): SessionRecord;
export function SessionRecord_serialize(obj: SessionRecord): Buffer;
export function SessionRecord_get_alice_base_key(obj: SessionRecord): Buffer;
export function SessionRecord_get_local_identity_key_public(obj: SessionRecord): Buffer;
export function SessionRecord_get_remote_identity_key_public(obj: SessionRecord): Buffer|null;
export function SessionRecord_get_sender_chain_key_value(obj: SessionRecord): Buffer;
export function Aes256GcmSiv_new(key: Buffer): Aes256GcmSiv;
export function Aes256GcmSiv_encrypt(aes_gcm_siv: Aes256GcmSiv, ptext: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
export function Aes256GcmSiv_decrypt(aes_gcm_siv: Aes256GcmSiv, ctext: Buffer, nonce: Buffer, associated_data: Buffer): Buffer;
