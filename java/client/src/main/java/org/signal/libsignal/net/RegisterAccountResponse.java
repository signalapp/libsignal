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
    return new ServiceId.Aci(guardedMap(Native::RegisterAccountResponse_GetAci));
  }

  /** Returns {@code null} for an account with no phone number. */
  public ServiceId.Pni getPni() {
    UUID pni = guardedMap(Native::RegisterAccountResponse_GetPni);
    return pni == null ? null : new ServiceId.Pni(pni);
  }

  /** Returns {@code null} for an account with no phone number. */
  public String getNumber() {
    return guardedMap(Native::RegisterAccountResponse_GetNumber);
  }

  /** Returns {@code null} for an account with a phone number. */
  public byte[] getAuthCredentialSalt() {
    return guardedMap(Native::RegisterAccountResponse_GetAuthCredentialSalt);
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
}
