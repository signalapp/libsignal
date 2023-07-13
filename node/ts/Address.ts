//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';

import * as uuid from 'uuid';

enum ServiceIdKind {
  Aci = 0,
  Pni,
}

const SERVICE_ID_FIXED_WIDTH_BINARY_LEN = 17;

// From https://github.com/Microsoft/TypeScript/issues/5863#issuecomment-1336204919,
// workaround for a static method returning a polymorphic type.
type ThisType<T extends { prototype: unknown }> = T['prototype'];

export class ServiceId extends Object {
  private readonly serviceIdFixedWidthBinary: Buffer;
  protected constructor(serviceIdFixedWidthBinary: Buffer) {
    super();
    if (serviceIdFixedWidthBinary.length != SERVICE_ID_FIXED_WIDTH_BINARY_LEN) {
      throw new TypeError('invalid Service-Id-FixedWidthBinary');
    }
    this.serviceIdFixedWidthBinary = serviceIdFixedWidthBinary;
  }

  protected static fromUuidBytesAndKind<T extends typeof ServiceId>(
    this: T,
    uuidBytes: ArrayLike<number>,
    kind: ServiceIdKind
  ): ThisType<T> {
    const buffer = Buffer.alloc(SERVICE_ID_FIXED_WIDTH_BINARY_LEN);
    buffer[0] = kind;
    buffer.set(uuidBytes, 1);
    return new this(buffer);
  }

  getServiceIdBinary(): Buffer {
    return Native.ServiceId_ServiceIdBinary(this.serviceIdFixedWidthBinary);
  }

  getServiceIdFixedWidthBinary(): Buffer {
    return Buffer.from(this.serviceIdFixedWidthBinary);
  }

  getServiceIdString(): string {
    return Native.ServiceId_ServiceIdString(this.serviceIdFixedWidthBinary);
  }

  override toString(): string {
    return Native.ServiceId_ServiceIdLog(this.serviceIdFixedWidthBinary);
  }

  static parseFromServiceIdFixedWidthBinary<T extends typeof ServiceId>(
    this: T,
    serviceIdFixedWidthBinary: Buffer
  ): ThisType<T> {
    let result: ServiceId;
    switch (serviceIdFixedWidthBinary[0]) {
      case ServiceIdKind.Aci:
        result = new Aci(serviceIdFixedWidthBinary);
        break;
      case ServiceIdKind.Pni:
        result = new Pni(serviceIdFixedWidthBinary);
        break;
      default:
        throw new TypeError('unknown type in Service-Id-FixedWidthBinary');
    }
    if ((result as object) instanceof this) {
      return result;
    }
    throw new TypeError(
      `expected ${this.name}, got ${result.constructor.name}`
    );
  }

  static parseFromServiceIdBinary(serviceIdBinary: Buffer): ServiceId {
    return ServiceId.parseFromServiceIdFixedWidthBinary(
      Native.ServiceId_ParseFromServiceIdBinary(serviceIdBinary)
    );
  }

  static parseFromServiceIdString(serviceIdString: string): ServiceId {
    return ServiceId.parseFromServiceIdFixedWidthBinary(
      Native.ServiceId_ParseFromServiceIdString(serviceIdString)
    );
  }

  getRawUuid(): string {
    return uuid.stringify(this.serviceIdFixedWidthBinary, 1);
  }

  getRawUuidBytes(): Buffer {
    return Buffer.from(this.serviceIdFixedWidthBinary.buffer, 1);
  }

  isEqual(other: ServiceId): boolean {
    return this.serviceIdFixedWidthBinary.equals(
      other.serviceIdFixedWidthBinary
    );
  }
}

export class Aci extends ServiceId {
  private readonly __type?: never;

  static fromUuid(uuidString: string): Aci {
    return this.fromUuidBytes(uuid.parse(uuidString));
  }

  static fromUuidBytes(uuidBytes: ArrayLike<number>): Aci {
    return super.fromUuidBytesAndKind(uuidBytes, ServiceIdKind.Aci);
  }
}

export class Pni extends ServiceId {
  private readonly __type?: never;

  static fromUuid(uuidString: string): Pni {
    return this.fromUuidBytes(uuid.parse(uuidString));
  }

  static fromUuidBytes(uuidBytes: ArrayLike<number>): Pni {
    return super.fromUuidBytesAndKind(uuidBytes, ServiceIdKind.Pni);
  }
}

export class ProtocolAddress {
  readonly _nativeHandle: Native.ProtocolAddress;

  private constructor(handle: Native.ProtocolAddress) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string | ServiceId, deviceId: number): ProtocolAddress {
    if (typeof name !== 'string') {
      name = name.getServiceIdString();
    }
    return new ProtocolAddress(Native.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return Native.ProtocolAddress_Name(this);
  }

  /**
   * Returns a ServiceId if this address contains a valid ServiceId, `null` otherwise.
   *
   * In a future release ProtocolAddresses will *only* support ServiceIds.
   */
  serviceId(): ServiceId | null {
    try {
      return ServiceId.parseFromServiceIdString(this.name());
    } catch {
      return null;
    }
  }

  deviceId(): number {
    return Native.ProtocolAddress_DeviceId(this);
  }

  toString(): string {
    return `${this.name()}.${this.deviceId()}`;
  }
}
