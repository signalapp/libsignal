//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-disable @typescript-eslint/require-await */

import * as SignalClient from '../../index.js';
import * as util from '../util.js';

util.initLogger();

export class InMemorySessionStore extends SignalClient.SessionStore {
  private state = new Map<string, Uint8Array>();
  async saveSession(
    name: SignalClient.ProtocolAddress,
    record: SignalClient.SessionRecord
  ): Promise<void> {
    const idx = `${name.name()}::${name.deviceId()}`;
    this.state.set(idx, record.serialize());
  }
  async getSession(
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.SessionRecord | null> {
    const idx = `${name.name()}::${name.deviceId()}`;
    const serialized = this.state.get(idx);
    if (serialized) {
      return SignalClient.SessionRecord.deserialize(serialized);
    } else {
      return null;
    }
  }
  async getExistingSessions(
    addresses: SignalClient.ProtocolAddress[]
  ): Promise<SignalClient.SessionRecord[]> {
    return addresses.map((address) => {
      const idx = `${address.name()}::${address.deviceId()}`;
      const serialized = this.state.get(idx);
      if (!serialized) {
        throw new Error(`no session for ${idx}`);
      }
      return SignalClient.SessionRecord.deserialize(serialized);
    });
  }
}

export class InMemoryIdentityKeyStore extends SignalClient.IdentityKeyStore {
  private idKeys = new Map<string, SignalClient.PublicKey>();
  private localRegistrationId: number;
  private identityKey: SignalClient.PrivateKey;

  constructor(localRegistrationId?: number) {
    super();
    this.identityKey = SignalClient.PrivateKey.generate();
    this.localRegistrationId = localRegistrationId ?? 5;
  }

  async getIdentityKey(): Promise<SignalClient.PrivateKey> {
    return this.identityKey;
  }
  async getLocalRegistrationId(): Promise<number> {
    return this.localRegistrationId;
  }

  async isTrustedIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey,
    _direction: SignalClient.Direction
  ): Promise<boolean> {
    const idx = `${name.name()}::${name.deviceId()}`;
    const currentKey = this.idKeys.get(idx);
    if (currentKey) {
      return currentKey.compare(key) == 0;
    } else {
      return true;
    }
  }

  async saveIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey
  ): Promise<SignalClient.IdentityChange> {
    const idx = `${name.name()}::${name.deviceId()}`;
    const currentKey = this.idKeys.get(idx);
    this.idKeys.set(idx, key);

    const changed = (currentKey?.compare(key) ?? 0) != 0;
    return changed
      ? SignalClient.IdentityChange.ReplacedExisting
      : SignalClient.IdentityChange.NewOrUnchanged;
  }
  async getIdentity(
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.PublicKey | null> {
    const idx = `${name.name()}::${name.deviceId()}`;
    return this.idKeys.get(idx) ?? null;
  }
}

export class InMemoryPreKeyStore extends SignalClient.PreKeyStore {
  private state = new Map<number, Uint8Array>();
  async savePreKey(
    id: number,
    record: SignalClient.PreKeyRecord
  ): Promise<void> {
    this.state.set(id, record.serialize());
  }
  async getPreKey(id: number): Promise<SignalClient.PreKeyRecord> {
    const record = this.state.get(id);
    if (!record) {
      throw new Error(`pre-key ${id} not found`);
    }
    return SignalClient.PreKeyRecord.deserialize(record);
  }
  async removePreKey(id: number): Promise<void> {
    this.state.delete(id);
  }
}

export class InMemorySignedPreKeyStore extends SignalClient.SignedPreKeyStore {
  private state = new Map<number, Uint8Array>();
  async saveSignedPreKey(
    id: number,
    record: SignalClient.SignedPreKeyRecord
  ): Promise<void> {
    this.state.set(id, record.serialize());
  }
  async getSignedPreKey(id: number): Promise<SignalClient.SignedPreKeyRecord> {
    const record = this.state.get(id);
    if (!record) {
      throw new Error(`pre-key ${id} not found`);
    }
    return SignalClient.SignedPreKeyRecord.deserialize(record);
  }
}

export class InMemoryKyberPreKeyStore extends SignalClient.KyberPreKeyStore {
  private state = new Map<number, Uint8Array>();
  private used = new Set<number>();
  private baseKeysSeen = new Map<bigint, SignalClient.PublicKey[]>();
  async saveKyberPreKey(
    id: number,
    record: SignalClient.KyberPreKeyRecord
  ): Promise<void> {
    this.state.set(id, record.serialize());
  }
  async getKyberPreKey(id: number): Promise<SignalClient.KyberPreKeyRecord> {
    const record = this.state.get(id);
    if (!record) {
      throw new Error(`kyber pre-key ${id} not found`);
    }
    return SignalClient.KyberPreKeyRecord.deserialize(record);
  }
  async markKyberPreKeyUsed(
    id: number,
    signedPreKeyId: number,
    baseKey: SignalClient.PublicKey
  ): Promise<void> {
    this.used.add(id);
    const bothKeyIds = (BigInt(id) << 32n) | BigInt(signedPreKeyId);
    const baseKeysSeen = this.baseKeysSeen.get(bothKeyIds);
    if (!baseKeysSeen) {
      this.baseKeysSeen.set(bothKeyIds, [baseKey]);
    } else if (baseKeysSeen.every((key) => key.compare(baseKey) != 0)) {
      baseKeysSeen.push(baseKey);
    } else {
      throw new Error('reused base key');
    }
  }
  async hasKyberPreKeyBeenUsed(id: number): Promise<boolean> {
    return this.used.has(id);
  }
}

export class InMemorySenderKeyStore extends SignalClient.SenderKeyStore {
  private state = new Map<string, SignalClient.SenderKeyRecord>();
  async saveSenderKey(
    sender: SignalClient.ProtocolAddress,
    distributionId: SignalClient.Uuid,
    record: SignalClient.SenderKeyRecord
  ): Promise<void> {
    const idx = `${distributionId}::${sender.name()}::${sender.deviceId()}`;
    this.state.set(idx, record);
  }
  async getSenderKey(
    sender: SignalClient.ProtocolAddress,
    distributionId: SignalClient.Uuid
  ): Promise<SignalClient.SenderKeyRecord | null> {
    const idx = `${distributionId}::${sender.name()}::${sender.deviceId()}`;
    return this.state.get(idx) ?? null;
  }
}

export default class TestStores {
  sender: InMemorySenderKeyStore;
  prekey: InMemoryPreKeyStore;
  signed: InMemorySignedPreKeyStore;
  kyber: InMemoryKyberPreKeyStore;
  identity: InMemoryIdentityKeyStore;
  session: InMemorySessionStore;

  constructor() {
    this.sender = new InMemorySenderKeyStore();
    this.prekey = new InMemoryPreKeyStore();
    this.signed = new InMemorySignedPreKeyStore();
    this.kyber = new InMemoryKyberPreKeyStore();
    this.identity = new InMemoryIdentityKeyStore();
    this.session = new InMemorySessionStore();
  }
}
