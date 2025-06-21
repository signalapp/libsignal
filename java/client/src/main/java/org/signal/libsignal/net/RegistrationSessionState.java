//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.time.Duration;
import java.util.Set;
import java.util.function.LongToIntFunction;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/** The state of a registration verification session as reported by the server. */
public class RegistrationSessionState extends NativeHandleGuard.SimpleOwner {
  RegistrationSessionState(long nativeHandle) {
    super(nativeHandle);
  }

  protected void release(long nativeHandle) {
    Native.RegistrationSession_Destroy(nativeHandle);
  }

  /** Whether a verification code is allowed to be requested for this session. */
  public boolean getAllowedToRequestCode() {
    return guardedMap(Native::RegistrationSession_GetAllowedToRequestCode);
  }

  /** Whether the session is verified. */
  public boolean getVerified() {
    return guardedMap(Native::RegistrationSession_GetVerified);
  }

  /**
   * How long the client should wait before requesting a call for verification.
   *
   * <p>Returns {@code null} if no waiting is requested.
   */
  public Duration getNextCall() {
    return ofOptionalDurationSeconds(Native::RegistrationSession_GetNextCallSeconds);
  }

  /**
   * How long the client should wait before requesting an SMS for verification.
   *
   * <p>Returns {@code null} if no waiting is requested.
   */
  public Duration getNextSms() {
    return ofOptionalDurationSeconds(Native::RegistrationSession_GetNextSmsSeconds);
  }

  /**
   * How long the client should wait before requesting an SMS for verification.
   *
   * <p>Returns {@code null} if no waiting is requested.
   */
  public Duration getNextVerificationAttempt() {
    return ofOptionalDurationSeconds(Native::RegistrationSession_GetNextVerificationAttemptSeconds);
  }

  /** Requested information that needs to be submitted before requesting code delivery. */
  public Set<ChallengeOption> getRequestedInformation() {
    return Set.of(
        (ChallengeOption[]) guardedMap(Native::RegistrationSession_GetRequestedInformation));
  }

  private Duration ofOptionalDurationSeconds(LongToIntFunction getter) {
    // Rust's None is returned as a negative value.
    int nextCallSeconds = guardedMap((handle) -> getter.applyAsInt(handle));
    if (nextCallSeconds < 0) {
      return null;
    }
    return Duration.ofSeconds(nextCallSeconds);
  }
}
