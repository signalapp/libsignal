//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.UUID;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;

/**
 * Typed representation of a Signal service ID, which can be one of various types.
 *
 * <p>Conceptually this is a UUID in a particular "namespace" representing a particular way to reach
 * a user on the Signal service.
 *
 * <p>The sort order for ServiceIds is first by kind (ACI, then PNI), then lexicographically by the
 * bytes of the UUID.
 */
public abstract class ServiceId implements Comparable<ServiceId> {
  private static final byte FIXED_WIDTH_BINARY_LENGTH = 17;

  private static final byte ACI_MARKER = 0x00;
  private static final byte PNI_MARKER = 0x01;

  byte[] storage;

  ServiceId(byte[] storage) {
    if (storage == null) {
      throw new IllegalArgumentException("Service-Id-FixedWidthBinary cannot be null");
    }
    this.storage = storage;
  }

  ServiceId(byte marker, UUID uuid) {
    if (uuid == null) {
      throw new IllegalArgumentException("Source UUID must be specified");
    }
    ByteBuffer bytes = ByteBuffer.wrap(new byte[FIXED_WIDTH_BINARY_LENGTH]);
    long high = uuid.getMostSignificantBits();
    long low = uuid.getLeastSignificantBits();
    bytes.put(marker);
    bytes.putLong(high);
    bytes.putLong(low);
    this.storage = bytes.array();
  }

  @Override
  public boolean equals(Object other) {
    if (other instanceof ServiceId) {
      return Arrays.equals(this.storage, ((ServiceId) other).storage);
    }
    return false;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.storage);
  }

  @Override
  public int compareTo(ServiceId other) {
    for (int i = 0; i < FIXED_WIDTH_BINARY_LENGTH; ++i) {
      // We specifically want to be doing an *unsigned* comparison of bytes, to match the Rust code
      // and other platforms.
      int comparisonResult = Byte.toUnsignedInt(storage[i]) - Byte.toUnsignedInt(other.storage[i]);
      if (comparisonResult != 0) {
        return comparisonResult;
      }
    }
    return 0;
  }

  @Override
  public String toString() {
    return this.toLogString();
  }

  public String toLogString() {
    return Native.ServiceId_ServiceIdLog(this.storage);
  }

  public byte[] toServiceIdBinary() {
    return Native.ServiceId_ServiceIdBinary(this.storage);
  }

  public byte[] toServiceIdFixedWidthBinary() {
    return this.storage.clone();
  }

  public String toServiceIdString() {
    return Native.ServiceId_ServiceIdString(this.storage);
  }

  public UUID getRawUUID() {
    ByteBuffer buffer = ByteBuffer.wrap(this.storage);
    byte unusedMarkerByte = buffer.get();
    return uuidFromBytes(buffer.slice());
  }

  public static ServiceId parseFromString(String serviceIdString) throws InvalidServiceIdException {
    if (serviceIdString == null) {
      throw new InvalidServiceIdException("Service-Id-String cannot be null");
    }
    byte[] storage;
    try {
      storage = filterExceptions(() -> Native.ServiceId_ParseFromServiceIdString(serviceIdString));
    } catch (IllegalArgumentException ex) {
      throw new InvalidServiceIdException();
    }
    return parseFromFixedWidthBinary(storage);
  }

  public static ServiceId parseFromBinary(byte[] serviceIdBinary) throws InvalidServiceIdException {
    if (serviceIdBinary == null) {
      throw new InvalidServiceIdException("Service-Id-Binary cannot be null");
    }
    byte[] storage;
    try {
      storage = filterExceptions(() -> Native.ServiceId_ParseFromServiceIdBinary(serviceIdBinary));
    } catch (IllegalArgumentException ex) {
      throw new InvalidServiceIdException();
    }
    return parseFromFixedWidthBinary(storage);
  }

  @CalledFromNative
  public static ServiceId parseFromFixedWidthBinary(byte[] storage)
      throws InvalidServiceIdException {
    if (storage == null) {
      throw new InvalidServiceIdException();
    }
    switch (storage[0]) {
      case ACI_MARKER:
        return new Aci(storage);
      case PNI_MARKER:
        return new Pni(storage);
      default:
        // This is already handled on the Rust side
        throw new InvalidServiceIdException();
    }
  }

  public static byte[] toConcatenatedFixedWidthBinary(Collection<ServiceId> serviceIds) {
    byte[] result = new byte[FIXED_WIDTH_BINARY_LENGTH * serviceIds.size()];
    int offset = 0;
    for (ServiceId next : serviceIds) {
      System.arraycopy(next.storage, 0, result, offset, FIXED_WIDTH_BINARY_LENGTH);
      offset += FIXED_WIDTH_BINARY_LENGTH;
    }
    return result;
  }

  private static UUID uuidFromBytes(ByteBuffer buffer) {
    long high = buffer.getLong();
    long low = buffer.getLong();
    return new UUID(high, low);
  }

  public static class InvalidServiceIdException extends Exception {
    public InvalidServiceIdException() {
      super();
    }

    public InvalidServiceIdException(String message) {
      super(message);
    }
  }

  public static final class Aci extends ServiceId {
    public Aci(UUID uuid) {
      super(ACI_MARKER, uuid);
    }

    Aci(byte[] storage) {
      super(storage);
    }

    public static Aci parseFromString(String serviceIdString) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromString(serviceIdString);
      if (result instanceof Aci) {
        return (Aci) result;
      }
      throw new InvalidServiceIdException();
    }

    public static Aci parseFromBinary(byte[] serviceIdBinary) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromBinary(serviceIdBinary);
      if (result instanceof Aci) {
        return (Aci) result;
      }
      throw new InvalidServiceIdException();
    }

    public static Aci parseFromFixedWidthBinary(byte[] storage) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromFixedWidthBinary(storage);
      if (result instanceof Aci) {
        return (Aci) result;
      }
      throw new InvalidServiceIdException();
    }
  }

  public static final class Pni extends ServiceId {
    public Pni(UUID uuid) {
      super(PNI_MARKER, uuid);
    }

    Pni(byte[] storage) {
      super(storage);
    }

    public static Pni parseFromString(String serviceIdString) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromString(serviceIdString);
      if (result instanceof Pni) {
        return (Pni) result;
      }
      throw new InvalidServiceIdException();
    }

    public static Pni parseFromBinary(byte[] serviceIdBinary) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromBinary(serviceIdBinary);
      if (result instanceof Pni) {
        return (Pni) result;
      }
      throw new InvalidServiceIdException();
    }

    public static Pni parseFromFixedWidthBinary(byte[] storage) throws InvalidServiceIdException {
      ServiceId result = ServiceId.parseFromFixedWidthBinary(storage);
      if (result instanceof Pni) {
        return (Pni) result;
      }
      throw new InvalidServiceIdException();
    }
  }
}
