//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.SignedPublicPreKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation;

/**
 * A client for the the registration service.
 *
 * <p>An instance of this class is tied to a single session ID that will be used for all requests.
 * To obtain a {@RegistrationService}, use {@link #createSession} or {@link #resumeSession} to begin
 * a new, or continue with an old session respectively.
 *
 * <p>{@link CompletableFuture}s returned by methods on this class can complete exceptionally with
 * any of the following exception types, in addition to any listed in the per-method documentation:
 *
 * <ul>
 *   <li>{@link RegistrationSessionNotFoundException} if the server rejects the session ID,
 *   <li>{@link ChatServiceException} if a request times out after being sent to the server,
 *   <li>{@link RetryLaterException} if the server responds with an HTTP 429,
 *   <li>{@link PossibleCaptiveNetworkException} if the server's TLS response suggests a captive
 *       network.
 *   <li>{@link RegistrationSessionIdInvalidException} if the session ID is invalid,
 *   <li>{@link RegistrationException} for other unexpected error responses
 * </ul>
 *
 * <p>There are four ways to register, along two axes: whether the account has a phone number, and
 * whether it already exists. Only {@link #registerAccount} needs a session, since proving control
 * of a phone number is an interactive process. {@link #reregisterAccount}, {@link
 * #registerAccountWithoutNumber}, and {@link #reregisterAccountWithoutNumber} each authenticate
 * with something the caller already holds, so they need no session and are static functions.
 *
 * <h2>Example</h2>
 *
 * <pre>
 * RegistrationService service =
 *     RegistrationService.createSession(network, new CreateSession(e164, fcmPushToken, mcc, mnc))
 *         .get();
 *
 * // Answer whatever getSessionState().getRequestedInformation() asks for, using
 * // requestPushChallenge()/submitPushChallenge() or submitCaptcha(), until
 * // getAllowedToRequestCode() is true.
 *
 * service.requestVerificationCode(VerificationTransport.SMS, "android", Locale.getDefault()).get();
 *
 * // A wrong code is not an error: the request succeeds and the session stays
 * // unverified, so check getSessionState().getVerified() before calling registerAccount.
 * service.submitVerificationCode(codeFromUser).get();
 *
 * RegisterAccountResponse response = service.registerAccount(accountPassword, ...).get();
 * </pre>
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

  @CalledFromNative
  public static enum Svr2CredentialsResult {
    MATCH,
    NO_MATCH,
    INVALID,
  }

  /**
   * Start a new registration session.
   *
   * <p>Returns a {@code CompletableFuture} that, on success, completes with an instance of this
   * class bound to the created session.
   *
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v1/verification/session}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
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
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a GET request to {@code
   * /v1/verification/session/{sessionId}}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
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
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a PATCH request to {@code
   * /v1/verification/session/{sessionId}}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
   */
  public CompletableFuture<Void> requestPushChallenge(String fcmPushToken) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_RequestPushChallenge(
                        asyncContextHandle, nativeHandle, fcmPushToken)));
  }

  /**
   * Submit the result of a push challenge.
   *
   * <p>The returned future resolves with {@code null} if the request is successful.
   *
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a PATCH request to {@code
   * /v1/verification/session/{sessionId}}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
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
   * in addition to the list of common exception types.
   *
   * <p>With the websocket transport, this makes a POST request to {@code
   * /v1/verification/session/{sessionId}/code}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
   */
  public CompletableFuture<Void> requestVerificationCode(
      VerificationTransport transport, String client, Locale locale) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_RequestVerificationCode(
                        asyncContextHandle,
                        nativeHandle,
                        transport.name().toLowerCase(),
                        client,
                        Network.languageCodesForLocale(locale))));
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
   * in addition to the list of common exception types.
   *
   * <p>With the websocket transport, this makes a PUT request to {@code
   * /v1/verification/session/{sessionId}/code}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
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
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a PATCH request to {@code
   * /v1/verification/session/{sessionId}}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
   */
  public CompletableFuture<Void> submitCaptcha(String captchaValue) {
    return guardedMap(
        nativeHandle ->
            tokioAsyncContext.guardedMap(
                asyncContextHandle ->
                    Native.RegistrationService_SubmitCaptcha(
                        asyncContextHandle, nativeHandle, captchaValue)));
  }

  /**
   * Check that the given list of SVR credentials is valid.
   *
   * <p>If the request succeeds, the returned future resolves with a map of submitted credential to
   * check result.
   *
   * <p>On failure, the future completes exceptionally.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v2/backup/auth/check}.
   *
   * @see RegistrationService {@code RegistrationService} lists the types of exceptions that can be
   *     thrown
   */
  public CompletableFuture<Map<String, Svr2CredentialsResult>> checkSvr2Credentials(
      String[] svrTokens) {
    return guardedMap(
            nativeHandle ->
                tokioAsyncContext.guardedMap(
                    asyncContextHandle ->
                        Native.RegistrationService_CheckSvr2Credentials(
                            asyncContextHandle, nativeHandle, svrTokens)))
        .thenApply(
            result -> {
              @SuppressWarnings("unchecked")
              var resultMap = (Map<String, Svr2CredentialsResult>) result;
              return resultMap;
            });
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

  /** Account attributes sent as part of a {@link #registerAccount} request. */
  public static class AccountAttributes extends NativeHandleGuard.SimpleOwner {
    public AccountAttributes(
        byte[] recoveryPassword,
        int aciRegistrationId,
        int pniRegistrationId,
        String registrationLock,
        byte[] unidentifiedAccessKey,
        boolean unrestrictedUnidentifiedAccess,
        Set<String> capabilities,
        boolean discoverableByPhoneNumber) {
      super(
          Native.RegistrationAccountAttributes_Create(
              recoveryPassword,
              aciRegistrationId,
              pniRegistrationId,
              registrationLock,
              unidentifiedAccessKey,
              unrestrictedUnidentifiedAccess,
              capabilities.toArray(String[]::new),
              discoverableByPhoneNumber));
    }

    protected void release(long nativeHandle) {
      Native.RegistrationAccountAttributes_Destroy(nativeHandle);
    }
  }

  /**
   * Send a register account request.
   *
   * <p>The returned future resolves to a {@link RegisterAccountResponse} if the request is
   * successful. If not, the future resolves with
   *
   * <ul>
   *   <li>{@link RegistrationLockException}
   *   <li>{@link DeviceTransferPossibleException}
   *   <li>{@link RegistrationRecoveryFailedException}
   *   <li>{@link RegisterAccountRequestRejectedException}
   *   <li>{@link RegistrationInvalidSessionException} if the session is unverified or no longer
   *       exists
   * </ul>
   *
   * in addition to the list of common exception types.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v1/registration}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
   */
  public CompletableFuture<RegisterAccountResponse> registerAccount(
      String accountPassword,
      boolean skipDeviceTransfer,
      AccountAttributes accountAttributes,
      String gcmPushToken,
      ECPublicKey aciPublicKey,
      ECPublicKey pniPublicKey,
      SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
      SignedPublicPreKey<ECPublicKey> pniSignedPreKey,
      SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey,
      SignedPublicPreKey<KEMPublicKey> pniPqLastResortPreKey) {

    var request =
        new RegisterAccountRequest(
            accountPassword,
            skipDeviceTransfer,
            gcmPushToken,
            aciPublicKey,
            pniPublicKey,
            aciSignedPreKey,
            pniSignedPreKey,
            aciPqLastResortPreKey,
            pniPqLastResortPreKey);

    return tokioAsyncContext
        .guardedMap(
            tokioContext ->
                accountAttributes.guardedMap(
                    attributesHandle ->
                        this.guardedMap(
                            service ->
                                request.guardedMap(
                                    register ->
                                        Native.RegistrationService_RegisterAccount(
                                            tokioContext, service, register, attributesHandle)))))
        .thenApply(responseHandle -> new RegisterAccountResponse(responseHandle));
  }

  /**
   * Send a request to re-register an account.
   *
   * <p>This is a static method since it uses the recovery password to authenticate instead of a
   * verification session. The returned future resolves to a {@link RegisterAccountResponse} if the
   * request is successful. If not, the future resolves with
   *
   * <ul>
   *   <li>{@link RegistrationLockException}
   *   <li>{@link DeviceTransferPossibleException}
   *   <li>{@link RegistrationRecoveryFailedException}
   *   <li>{@link RegisterAccountRequestRejectedException}
   * </ul>
   *
   * in addition to the list of common exception types.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v1/registration}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
   */
  public static CompletableFuture<RegisterAccountResponse> reregisterAccount(
      Network network,
      String number,
      String accountPassword,
      boolean skipDeviceTransfer,
      AccountAttributes accountAttributes,
      String gcmPushToken,
      ECPublicKey aciPublicKey,
      ECPublicKey pniPublicKey,
      SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
      SignedPublicPreKey<ECPublicKey> pniSignedPreKey,
      SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey,
      SignedPublicPreKey<KEMPublicKey> pniPqLastResortPreKey) {

    var request =
        new RegisterAccountRequest(
            accountPassword,
            skipDeviceTransfer,
            gcmPushToken,
            aciPublicKey,
            pniPublicKey,
            aciSignedPreKey,
            pniSignedPreKey,
            aciPqLastResortPreKey,
            pniPqLastResortPreKey);

    var tokioAsyncContext = network.getAsyncContext();

    return tokioAsyncContext
        .guardedMap(
            tokioContext ->
                accountAttributes.guardedMap(
                    attributesHandle ->
                        request.guardedMap(
                            register ->
                                Native.RegistrationService_ReregisterAccount(
                                    tokioContext,
                                    network.getConnectionManager(),
                                    number,
                                    register,
                                    attributesHandle))))
        .thenApply(responseHandle -> new RegisterAccountResponse(responseHandle));
  }

  /**
   * Send a request to register an account that has no phone number.
   *
   * <p>{@code accountAttributes.recoveryPassword} must not be empty, since a recovery password is
   * the only way such an account can ever be recovered.
   *
   * <p>The returned future resolves to a {@link RegisterAccountResponse} if the request is
   * successful. If not, the future resolves with
   *
   * <ul>
   *   <li>{@link RegistrationRecoveryPasswordRequiredException} if the recovery password is empty
   *   <li>{@link RegisterAccountRequestRejectedException} if the receipt credential presentation
   *       can't be parsed
   *   <li>{@link RegistrationInvalidReceiptException} if the receipt credential presentation fails
   *       verification, has expired, or has already been redeemed
   * </ul>
   *
   * in addition to the list of common network/chat exception types.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v1/registration}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
   */
  public static CompletableFuture<RegisterAccountResponse> registerAccountWithoutNumber(
      Network network,
      ReceiptCredentialPresentation receiptCredentialPresentation,
      String accountPassword,
      boolean skipDeviceTransfer,
      AccountAttributes accountAttributes,
      String gcmPushToken,
      ECPublicKey aciPublicKey,
      SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
      SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey) {

    var request =
        new RegisterAccountRequest(
            accountPassword,
            skipDeviceTransfer,
            gcmPushToken,
            aciPublicKey,
            aciSignedPreKey,
            aciPqLastResortPreKey);

    var tokioAsyncContext = network.getAsyncContext();

    return tokioAsyncContext
        .guardedMap(
            tokioContext ->
                accountAttributes.guardedMap(
                    attributesHandle ->
                        request.guardedMap(
                            register ->
                                Native.RegistrationService_RegisterAccountWithoutNumber(
                                    tokioContext,
                                    network.getConnectionManager(),
                                    receiptCredentialPresentation.getInternalContentsForJNI(),
                                    register,
                                    attributesHandle))))
        .thenApply(responseHandle -> new RegisterAccountResponse(responseHandle));
  }

  /**
   * Send a request to re-register an account that has no phone number, identified by its ACI.
   *
   * <p>The counterpart to {@link #reregisterAccount} for an account with no phone number. No PNI
   * keys are accepted here; libsignal generates the PNI material the server requires and then
   * discards. {@code accountAttributes.recoveryPassword} must not be empty, since a recovery
   * password is the only way such an account can ever be re-registered.
   *
   * <p>The returned future resolves to a {@link RegisterAccountResponse} if the request is
   * successful. If not, the future resolves with
   *
   * <ul>
   *   <li>{@link RegistrationRecoveryPasswordRequiredException}
   *   <li>{@link RegistrationOneTimePasswordRequiredException}
   *   <li>{@link RegistrationRecoveryFailedException}
   *   <li>{@link RegisterAccountRequestRejectedException}
   * </ul>
   *
   * in addition to the list of common exception types.
   *
   * <p>{@code oneTimePassword} is sent as a number, so {@code 012345} becomes {@code 12345}. Can be
   * {@code null} if no TOTP was set up for the account.
   *
   * <p>With the websocket transport, this makes a POST request to {@code /v1/registration}.
   *
   * @see RegistrationService {@code RegistrationService} lists the common types of exceptions that
   *     can be thrown
   */
  public static CompletableFuture<RegisterAccountResponse> reregisterAccountWithoutNumber(
      Network network,
      ServiceId.Aci aci,
      String accountPassword,
      boolean skipDeviceTransfer,
      Integer oneTimePassword,
      AccountAttributes accountAttributes,
      String gcmPushToken,
      ECPublicKey aciPublicKey,
      SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
      SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey) {

    var request =
        new RegisterAccountRequest(
            accountPassword,
            skipDeviceTransfer,
            gcmPushToken,
            aciPublicKey,
            aciSignedPreKey,
            aciPqLastResortPreKey);

    if (oneTimePassword != null) {
      request.setOneTimePassword(oneTimePassword);
    }

    var tokioAsyncContext = network.getAsyncContext();

    return tokioAsyncContext
        .guardedMap(
            tokioContext ->
                accountAttributes.guardedMap(
                    attributesHandle ->
                        request.guardedMap(
                            register ->
                                Native.RegistrationService_ReregisterAccountWithoutNumber(
                                    tokioContext,
                                    network.getConnectionManager(),
                                    aci.toServiceIdFixedWidthBinary(),
                                    register,
                                    attributesHandle))))
        .thenApply(responseHandle -> new RegisterAccountResponse(responseHandle));
  }

  /** Test-only; sends a {@link CreateSession} request to a {@FakeChatServer} to start a session. */
  static CompletableFuture<RegistrationService> fakeCreateSession(
      FakeChatServer fakeServer, CreateSession createSession) {
    var asyncContext = fakeServer.getTokioContext();
    return asyncContext
        .guardedMap(
            tokioContext ->
                fakeServer.guardedMap(
                    fakeChat ->
                        NativeTesting.TESTING_FakeRegistrationSession_CreateSession(
                            tokioContext, createSession, fakeChat)))
        .thenApply(registration -> new RegistrationService(registration, asyncContext));
  }

  private static class RegisterAccountRequest extends NativeHandleGuard.SimpleOwner {
    public RegisterAccountRequest() {
      super(Native.RegisterAccountRequest_Create());
    }

    /** Builds a request with ACI keys only, for an account that will have no PNI. */
    public RegisterAccountRequest(
        String accountPassword,
        boolean skipDeviceTransfer,
        String gcmPushToken,
        ECPublicKey aciPublicKey,
        SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
        SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey) {
      this();
      final int ACI = ServiceId.Kind.ACI.ordinal();

      this.guardedRun(
          requestHandle -> {
            Native.RegisterAccountRequest_SetAccountPassword(requestHandle, accountPassword);
            Native.RegisterAccountRequest_SetGcmPushToken(requestHandle, gcmPushToken);
            aciPublicKey.guardedRun(
                handle ->
                    Native.RegisterAccountRequest_SetIdentityPublicKey(requestHandle, ACI, handle));

            Native.RegisterAccountRequest_SetIdentitySignedPreKey(
                requestHandle, ACI, aciSignedPreKey);

            Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
                requestHandle, ACI, aciPqLastResortPreKey);

            if (skipDeviceTransfer) {
              Native.RegisterAccountRequest_SetSkipDeviceTransfer(requestHandle);
            }
          });
    }

    public RegisterAccountRequest(
        String accountPassword,
        boolean skipDeviceTransfer,
        String gcmPushToken,
        ECPublicKey aciPublicKey,
        ECPublicKey pniPublicKey,
        SignedPublicPreKey<ECPublicKey> aciSignedPreKey,
        SignedPublicPreKey<ECPublicKey> pniSignedPreKey,
        SignedPublicPreKey<KEMPublicKey> aciPqLastResortPreKey,
        SignedPublicPreKey<KEMPublicKey> pniPqLastResortPreKey) {
      this(
          accountPassword,
          skipDeviceTransfer,
          gcmPushToken,
          aciPublicKey,
          aciSignedPreKey,
          aciPqLastResortPreKey);
      final int PNI = ServiceId.Kind.PNI.ordinal();

      this.guardedRun(
          requestHandle -> {
            pniPublicKey.guardedRun(
                handle ->
                    Native.RegisterAccountRequest_SetIdentityPublicKey(requestHandle, PNI, handle));

            Native.RegisterAccountRequest_SetIdentitySignedPreKey(
                requestHandle, PNI, pniSignedPreKey);

            Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
                requestHandle, PNI, pniPqLastResortPreKey);
          });
    }

    private void setOneTimePassword(int oneTimePassword) {
      this.guardedRun(
          requestHandle ->
              Native.RegisterAccountRequest_SetOneTimePassword(requestHandle, oneTimePassword));
    }

    protected void release(long nativeHandle) {
      Native.RegisterAccountRequest_Destroy(nativeHandle);
    }
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
