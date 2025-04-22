//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.time.Duration;
import java.util.UUID;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ServiceId;

public class RegisterAccountResponse extends NativeHandleGuard.SimpleOwner {
  public static record BadgeEntitlement(String id, boolean visible, Duration expiration) {
    @CalledFromNative
    private BadgeEntitlement(String id, boolean visible, long expirationSeconds) {
      this(id, visible, Duration.ofSeconds(expirationSeconds));
    }
  }

  public static record BackupEntitlement(long backupLevel, Duration expiration) {}

  RegisterAccountResponse(long nativeHandle) {
    super(nativeHandle);
  }

  @Override
  protected void release(long nativeHandle) {
    Native.RegisterAccountResponse_Destroy(nativeHandle);
  }

  public BackupEntitlement getBackupEntitlement() {
    return guardedMap(
        nativeHandle ->
            new BackupEntitlement(
                Native.RegisterAccountResponse_GetEntitlementBackupLevel(nativeHandle),
                Duration.ofSeconds(
                    Native.RegisterAccountResponse_GetEntitlementBackupExpirationSeconds(
                        nativeHandle))));
  }

  public BadgeEntitlement[] getBadgeEntitlements() {
    return (BadgeEntitlement[]) guardedMap(Native::RegisterAccountResponse_GetEntitlementBadges);
  }

  public ServiceId.Aci getAci() {
    return (ServiceId.Aci) this.getIdentity(ServiceId.Kind.ACI);
  }

  public ServiceId.Pni getPni() {
    return (ServiceId.Pni) this.getIdentity(ServiceId.Kind.PNI);
  }

  public String getNumber() {
    return guardedMap(Native::RegisterAccountResponse_GetNumber);
  }

  public boolean isReregistration() {
    return guardedMap(Native::RegisterAccountResponse_GetReregistration);
  }

  public boolean isStorageCapable() {
    return guardedMap(Native::RegisterAccountResponse_GetStorageCapable);
  }

  public byte[] getUsernameHash() {
    return guardedMap(Native::RegisterAccountResponse_GetUsernameHash);
  }

  public UUID getUsernameLinkHandle() {
    return guardedMap(Native::RegisterAccountResponse_GetUsernameLinkHandle);
  }

  private ServiceId getIdentity(ServiceId.Kind kind) {
    try {
      return ServiceId.parseFromFixedWidthBinary(
          guardedMap(
              nativeHandle ->
                  Native.RegisterAccountResponse_GetIdentity(nativeHandle, kind.ordinal())));

    } catch (ServiceId.InvalidServiceIdException e) {
      // This is prevented by the Rust side.
      return null;
    }
  }
}
