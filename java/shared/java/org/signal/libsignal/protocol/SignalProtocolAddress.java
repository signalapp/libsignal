/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class SignalProtocolAddress implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public SignalProtocolAddress(String name, int deviceId) {
    this.unsafeHandle = Native.ProtocolAddress_New(name, deviceId);
  }

  public SignalProtocolAddress(ServiceId serviceId, int deviceId) {
    this(serviceId.toServiceIdString(), deviceId);
  }

  public SignalProtocolAddress(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ProtocolAddress_Destroy(this.unsafeHandle);
  }

  public String getName() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ProtocolAddress_Name(guard.nativeHandle());
    }
  }

  /**
   * Returns a ServiceId if this address contains a valid ServiceId, {@code null} otherwise.
   *
   * In a future release SignalProtocolAddresses will <em>only</em> support ServiceIds.
   */
  public ServiceId getServiceId() {
    try {
      return ServiceId.parseFromString(getName());
    } catch (ServiceId.InvalidServiceIdException e) {
      return null;
    }
  }

  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ProtocolAddress_DeviceId(guard.nativeHandle());
    }
  }

  @Override
  public String toString() {
    return getName() + "." + getDeviceId();
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                       return false;
    if (!(other instanceof SignalProtocolAddress)) return false;

    SignalProtocolAddress that = (SignalProtocolAddress)other;
    return this.getName().equals(that.getName()) && this.getDeviceId() == that.getDeviceId();
  }

  @Override
  public int hashCode() {
    return this.getName().hashCode() ^ this.getDeviceId();
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
