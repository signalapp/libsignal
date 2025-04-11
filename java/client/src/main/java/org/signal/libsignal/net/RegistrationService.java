//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Locale;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.protocol.util.Pair;

/**
 * A client for the the registration service.
 *
 * <p>An instance of this class is tied to a single session ID that will be used for all requests.
 * To obtain a {@RegistrationService}, use {@link #createSession} or {@link #resumeSession} to begin
 * a new, or continue with an old session respectively.
 *
 * <p>{@link CompletableFuture}s returned by methods on this class can complete exceptionally with
 * any of the following exception types, in addition to those listed in the method documentation:
 *
 * <ul>
 *   <li>{@link RegistrationSessionNotFoundException} if the server rejects the session ID,
 *   <li>{@link ChatServiceException} if a request times out after being sent to the server,
 *   <li>{@link RetryLaterException} if the server responds with an HTTP 429,
 *   <li>{@link RegistrationSessionIdInvalidException} if the session ID is invalid,
 *   <li>{@link RegistrationException} for other unexpected error responses,
 * </ul>
 */
public class RegistrationService extends NativeHandleGuard.SimpleOwner {
  /** Values passed to the server by {@link #createSession}. */
  public static record CreateSession(
      /** The E164-formatted phone number being registered */
      String number,
      /** The FCM push token used to receive messages. */
      String fcmPushToken,
      String mcc,
      String mnc) {}

  public static enum VerificationTransport {
    SMS,
    VOICE;
  }

  /**
   * Start a new registration session.
   *
   * <p>Returns a {@code CompletableFuture} that, on success, completes with an instance of this
   * class bound to the created session.
   *
   * <p>On failure, the future completes exceptionally with one of the previously listed exception
   * types.
   */
  public static CompletableFuture<RegistrationService> createSession(
      Network network, CreateSession createSession) {
    var tokioAsyncContext = network.getAsyncContext();
    return tokioAsyncContext
        .guardedMap(
            asyncContext ->
                Native.RegistrationService_CreateSession(
                    asyncContext, createSession, network.getConnectionManager()))
        .thenApply(nativeHandle -> new RegistrationService(nativeHandle, tokioAsyncContext));
  }

  /**
   * Resume an existing registration session.
   *
   * <p>Returns a {@code CompletableFuture} that, on success, completes with an instance of this
   * class bound to the resumed session.
   *
   * <p>On failure, the future completes exceptionally with one of the previously listed exception
   * types.
   */
  public static CompletableFuture<RegistrationService> resumeSession(
      Network network, String sessionId, String number) {
    var tokioAsyncContext = network.getAsyncContext();
    return tokioAsyncContext
        .guardedMap(
            asyncContext ->
                Native.RegistrationService_ResumeSession(
                    asyncContext, sessionId, number, network.getConnectionManager()))
        .thenApply(nativeHandle -> new RegistrationService(nativeHandle, tokioAsyncContext));
  }

  /**
   * Request a push challenge sent to the provided FCM token.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally with one of the previously listed exception
   * types.
   */
  public CompletableFuture<Void> requestPushChallenge(String fcmPushToken) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_RequestPushChallenge(
                        asyncContextHandle, nativeHandle, fcmPushToken, null)));
  }

  /**
   * Submit the result of a push challenge.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally with one of the previously listed exception
   * types.
   */
  public CompletableFuture<Void> submitPushChallenge(String pushChallenge) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_SubmitPushChallenge(
                        asyncContextHandle, nativeHandle, pushChallenge)));
  }

  /**
   * Request that a verification code be sent via the given transport method.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally with
   *
   * <ul>
   *   <li>{@link RegistrationSessionNotReadyException}
   *   <li>{@link RegistrationSessionSendCodeException}
   *   <li>{@link RegistrationCodeNotDeliverableException}
   * </ul>
   *
   * or one of the previously listed exception types.
   */
  public CompletableFuture<Void> requestVerificationCode(
      VerificationTransport transport, String client, Locale locale) {
    var languages =
        locale == null
            ? new String[0]
            : new String[] {locale.getLanguage() + "-" + locale.getCountry()};
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_RequestVerificationCode(
                        asyncContextHandle,
                        nativeHandle,
                        transport.name().toLowerCase(),
                        client,
                        languages)));
  }

  /**
   * Submit a received verification code.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally with
   *
   * <ul>
   *   <li>{@link RegistrationSessionNotReadyException}
   * </ul>
   *
   * or one of the previously listed exception types.
   */
  public CompletableFuture<Void> submitVerificationCode(String code) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_SubmitVerificationCode(
                        asyncContextHandle, nativeHandle, code)));
  }

  /**
   * Submit the result of a completed captcha challenge.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally with one of {@link RegistrationException},
   * {@link RegistrationSessionIdInvalidException}, or {@link ChatServiceException} (if the request
   * times out).
   */
  public CompletableFuture<Void> submitCaptcha(String captchaValue) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_SubmitCaptcha(
                        asyncContextHandle, nativeHandle, captchaValue)));
  }

  /** Get the ID for this registration validation session. */
  public String getSessionId() {
    return guardedMap(Native::RegistrationService_SessionId);
  }

  /** Get the session state received from the server with the last completed validation request. */
  public RegistrationSessionState getSessionState() {
    return guardedMap(
        nativeHandle ->
            new RegistrationSessionState(
                Native.RegistrationService_RegistrationSession(nativeHandle)));
  }

  static Pair<FakeChatServer, CompletableFuture<RegistrationService>> fakeCreateSession(
      TokioAsyncContext asyncContext, CreateSession createSession) {
    var fakeServer = new FakeChatServer(asyncContext);
    var createSessionFut =
        asyncContext
            .guardedMap(
                tokioContext ->
                    fakeServer.guardedMap(
                        fakeChat ->
                            NativeTesting.TESTING_FakeRegistrationSession_CreateSession(
                                tokioContext, createSession, fakeChat)))
            .thenApply(registration -> new RegistrationService(registration, asyncContext));

    return new Pair<>(fakeServer, createSessionFut);
  }

  private TokioAsyncContext tokioAsyncContext;

  private RegistrationService(long nativeHandle, TokioAsyncContext tokioAsyncContext) {
    super(nativeHandle);
    this.tokioAsyncContext = tokioAsyncContext;
  }

  protected void release(long nativeHandle) {
    Native.RegistrationService_Destroy(nativeHandle);
  }
}
