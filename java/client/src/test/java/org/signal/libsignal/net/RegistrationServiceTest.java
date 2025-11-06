//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Test;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.SignedPublicPreKey;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.signal.libsignal.util.Base64;

public class RegistrationServiceTest {

  private static class FakeRegistrationException extends Exception {}

  private interface ThrowingConsumer<T> {
    void accept(T value) throws Exception;
  }

  @Test
  public void testConvertRegistrationSessionInfo() throws Exception {
    var info = new RegistrationSessionState(NativeTesting.TESTING_RegistrationSessionInfoConvert());
    assertEquals(info.getAllowedToRequestCode(), true);
    assertEquals(info.getVerified(), true);
    assertEquals(info.getNextCall(), Duration.ofSeconds(123));
    assertEquals(info.getNextSms(), Duration.ofSeconds(456));
    assertEquals(info.getNextVerificationAttempt(), Duration.ofSeconds(789));
    assertEquals(info.getRequestedInformation(), EnumSet.of(ChallengeOption.PUSH_CHALLENGE));
  }

  @Test
  public void testConvertSignedPreKey() {
    var key = ECKeyPair.generate().getPublicKey();
    var signedPublicPreKey = new SignedPublicPreKey<>(42, key, "signature".getBytes());
    key.guardedRun(
        keyHandle ->
            NativeTesting.TESTING_SignedPublicPreKey_CheckBridgesCorrectly(
                keyHandle, signedPublicPreKey));
  }

  @Test
  public void testConvertCheckSvr2CredentialsResponse() {
    var response = NativeTesting.TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert();
    assertEquals(
        Map.of(
            "username:pass-match", RegistrationService.Svr2CredentialsResult.MATCH,
            "username:pass-no-match", RegistrationService.Svr2CredentialsResult.NO_MATCH,
            "username:pass-invalid", RegistrationService.Svr2CredentialsResult.INVALID),
        response);
  }

  @Test
  public void testConvertRegistrationResponse() throws Exception {
    var response =
        new RegisterAccountResponse(
            NativeTesting.TESTING_RegisterAccountResponse_CreateTestValue());
    assertEquals(response.getNumber(), "+18005550123");
    assertEquals(
        response.getAci(), ServiceId.Aci.parseFromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    assertEquals(
        response.getPni(),
        ServiceId.Pni.parseFromString("PNI:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
    assertArrayEquals(response.getUsernameHash(), "username-hash".getBytes());
    assertEquals(
        response.getUsernameLinkHandle(), UUID.fromString("55555555-5555-5555-5555-555555555555"));
    assertEquals(response.isStorageCapable(), true);
    assertArrayEquals(
        response.getBadgeEntitlements(),
        new RegisterAccountResponse.BadgeEntitlement[] {
          new RegisterAccountResponse.BadgeEntitlement("first", true, Duration.ofSeconds(123456)),
          new RegisterAccountResponse.BadgeEntitlement("second", false, Duration.ofSeconds(555)),
        });
    assertEquals(
        response.getBackupEntitlement(),
        new RegisterAccountResponse.BackupEntitlement(123, Duration.ofSeconds(888888)));
    assertEquals(response.isReregistration(), true);
  }

  @Test
  public void testCreateSessionErrorConversion() {
    assertRegistrationSessionErrorIs(
        "InvalidSessionId",
        RegistrationSessionIdInvalidException.class,
        NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
    assertIsRetryAfterError(NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
    assertIsTimeoutError(NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
    assertIsUnknownError(NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
    assertIsServerSideError(NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
    assertIsPushChallengeError(
        NativeTesting::TESTING_RegistrationService_CreateSessionErrorConvert);
  }

  @Test
  public void testResumeSessionErrorConversion() {
    assertRegistrationSessionErrorIs(
        "InvalidSessionId",
        RegistrationSessionIdInvalidException.class,
        NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
    assertRegistrationSessionErrorIs(
        "SessionNotFound",
        RegistrationSessionNotFoundException.class,
        NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
    assertIsTimeoutError(NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
    assertIsUnknownError(NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
    assertIsServerSideError(NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
    assertIsPushChallengeError(
        NativeTesting::TESTING_RegistrationService_ResumeSessionErrorConvert);
  }

  @Test
  public void testUpdateSessionErrorConversion() {
    assertRegistrationSessionErrorIs(
        "Rejected",
        RegistrationException.class,
        NativeTesting::TESTING_RegistrationService_UpdateSessionErrorConvert);
    assertIsRetryAfterError(NativeTesting::TESTING_RegistrationService_UpdateSessionErrorConvert);
    assertIsTimeoutError(NativeTesting::TESTING_RegistrationService_UpdateSessionErrorConvert);
    assertIsUnknownError(NativeTesting::TESTING_RegistrationService_UpdateSessionErrorConvert);
    assertIsServerSideError(NativeTesting::TESTING_RegistrationService_UpdateSessionErrorConvert);
  }

  @Test
  public void testRequestVerificationCodeErrorConversion() {
    assertRegistrationSessionErrorIs(
        "InvalidSessionId",
        RegistrationSessionIdInvalidException.class,
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertRegistrationSessionErrorIs(
        "SessionNotFound",
        RegistrationSessionNotFoundException.class,
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertRegistrationSessionErrorIs(
        "NotReadyForVerification",
        RegistrationSessionNotReadyException.class,
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertRegistrationSessionErrorIs(
        "SendFailed",
        RegistrationSessionSendCodeException.class,
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);

    var notDeliverableException =
        assertRegistrationSessionErrorIs(
            "CodeNotDeliverable",
            RegistrationCodeNotDeliverableException.class,
            NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertEquals(notDeliverableException.reason, "no reason");
    assertEquals(notDeliverableException.permanentFailure, true);

    assertIsRetryAfterError(
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertIsTimeoutError(
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertIsUnknownError(
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
    assertIsServerSideError(
        NativeTesting::TESTING_RegistrationService_RequestVerificationCodeErrorConvert);
  }

  @Test
  public void testSubmitVerificationErrorConversion() {
    assertRegistrationSessionErrorIs(
        "InvalidSessionId",
        RegistrationSessionIdInvalidException.class,
        NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertRegistrationSessionErrorIs(
        "SessionNotFound",
        RegistrationSessionNotFoundException.class,
        NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertRegistrationSessionErrorIs(
        "NotReadyForVerification",
        RegistrationSessionNotReadyException.class,
        NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertIsRetryAfterError(
        NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertIsTimeoutError(NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertIsUnknownError(NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
    assertIsServerSideError(
        NativeTesting::TESTING_RegistrationService_SubmitVerificationErrorConvert);
  }

  @Test
  public void testCheckSvr2CredentialsErrorConversion() {
    assertRegistrationSessionErrorIs(
        "CredentialsCouldNotBeParsed",
        RegistrationException.class,
        NativeTesting::TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert);
    assertIsTimeoutError(
        NativeTesting::TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert);
    assertIsUnknownError(
        NativeTesting::TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert);
    assertIsServerSideError(
        NativeTesting::TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert);
  }

  @Test
  public void testRegisterAccountErrorConversion() {
    assertRegistrationSessionErrorIs(
        "DeviceTransferIsPossibleButNotSkipped",
        DeviceTransferPossibleException.class,
        NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertRegistrationSessionErrorIs(
        "RegistrationRecoveryVerificationFailed",
        RegistrationRecoveryFailedException.class,
        NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertRegistrationSessionErrorIs(
        "RegistrationLockFor50Seconds",
        RegistrationLockException.class,
        NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertIsRetryAfterError(NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertIsTimeoutError(NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertIsUnknownError(NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
    assertIsServerSideError(NativeTesting::TESTING_RegistrationService_RegisterAccountErrorConvert);
  }

  private static <E extends Throwable> E assertRegistrationSessionErrorIs(
      String errorDescription, Class<E> expectedErrorType, ThrowingConsumer<String> throwError) {
    return assertThrows(
        "for " + errorDescription, expectedErrorType, () -> throwError.accept(errorDescription));
  }

  private static void assertIsRetryAfterError(ThrowingConsumer<String> throwError) {
    RetryLaterException e =
        assertRegistrationSessionErrorIs(
            "RetryAfter42Seconds", RetryLaterException.class, throwError);
    assertEquals(e.duration, Duration.ofSeconds(42));
  }

  private static void assertIsTimeoutError(ThrowingConsumer<String> throwError) {
    assertRegistrationSessionErrorIs("Timeout", ChatServiceException.class, throwError);
  }

  private static void assertIsUnknownError(ThrowingConsumer<String> throwError) {
    RegistrationException e =
        assertRegistrationSessionErrorIs("Unknown", RegistrationException.class, throwError);
    assertEquals(e.getMessage(), "some message");
  }

  private static void assertIsServerSideError(ThrowingConsumer<String> throwError) {
    RegistrationException e =
        assertRegistrationSessionErrorIs(
            "ServerSideError", RegistrationException.class, throwError);
    assertThat(e.getMessage(), containsString("server-side error"));
  }

  private static void assertIsPushChallengeError(ThrowingConsumer<String> throwError) {
    RateLimitChallengeException e =
        assertRegistrationSessionErrorIs(
            "PushChallenge", RateLimitChallengeException.class, throwError);
    assertEquals(e.getToken(), "token");
    assertEquals(e.getOptions(), EnumSet.of(ChallengeOption.PUSH_CHALLENGE));
  }

  @Test
  public void testFakeRemoteCreateSession() throws ExecutionException, InterruptedException {
    var tokio = new TokioAsyncContext();
    var fakeServer = new FakeChatServer(tokio);
    var createSession =
        RegistrationService.fakeCreateSession(
            fakeServer,
            new RegistrationService.CreateSession("+18005550123", "myPushToken", null, null));

    var fakeRemote = fakeServer.getNextRemote().get();
    var firstRequestAndId = fakeRemote.getNextIncomingRequest().get();
    assertNotNull(firstRequestAndId);
    var firstRequest = firstRequestAndId.getFirst();

    assertEquals(firstRequest.getMethod(), "POST");
    assertEquals(firstRequest.getPathAndQuery(), "/v1/verification/session");

    fakeRemote.sendResponse(
        firstRequestAndId.getSecond(),
        200,
        "OK",
        new String[] {"content-type: application/json"},
        """
        {
            "allowedToRequestCode": true,
            "verified": false,
            "requestedInformation": ["pushChallenge", "captcha"],
            "id": "fake-session-A"
        }
        """
            .getBytes());

    var session = createSession.get();
    assertEquals(session.getSessionId(), "fake-session-A");

    var sessionState = session.getSessionState();
    assertEquals(sessionState.getVerified(), false);
    assertEquals(
        sessionState.getRequestedInformation(),
        Set.of(ChallengeOption.PUSH_CHALLENGE, ChallengeOption.CAPTCHA));

    var requestVerification =
        session.requestVerificationCode(
            RegistrationService.VerificationTransport.VOICE,
            "libsignal test",
            Locale.CANADA_FRENCH);

    var secondRequestAndId = fakeRemote.getNextIncomingRequest().get();
    assertNotNull(secondRequestAndId);
    var secondRequest = secondRequestAndId.getFirst();

    assertEquals(secondRequest.getMethod(), "POST");
    assertEquals(secondRequest.getPathAndQuery(), "/v1/verification/session/fake-session-A/code");
    assertEquals(
        new String(secondRequest.getBody()),
        """
        {"transport":"voice","client":"libsignal test"}""");
    assertEquals(
        secondRequest.getHeaders(),
        Map.of("content-type", "application/json", "accept-language", "fr-CA"));

    fakeRemote.sendResponse(
        secondRequestAndId.getSecond(),
        200,
        "OK",
        new String[] {"content-type: application/json"},
        """
        {
            "allowedToRequestCode": true,
            "verified": false,
            "requestedInformation": ["pushChallenge", "captcha"],
            "id": "fake-session-A"
        }
        """
            .getBytes());

    requestVerification.get();
  }

  @Test
  public void testFakeRemoteRegisterAccount()
      throws ExecutionException, InterruptedException, ParseException {
    var tokio = new TokioAsyncContext();
    var fakeServer = new FakeChatServer(tokio);
    var createSession =
        RegistrationService.fakeCreateSession(
            fakeServer,
            new RegistrationService.CreateSession("+18005550123", "myPushToken", null, null));

    var fakeRemote = fakeServer.getNextRemote().get();
    var firstRequestAndId = fakeRemote.getNextIncomingRequest().get();
    assertNotNull(firstRequestAndId);

    // Send a response to allow the request to complete.
    fakeRemote.sendResponse(
        firstRequestAndId.getSecond(),
        200,
        "OK",
        new String[] {"content-type: application/json"},
        """
        {
            "allowedToRequestCode": true,
            "verified": false,
            "requestedInformation": ["pushChallenge", "captcha"],
            "id": "fake-session-A"
        }
        """
            .getBytes());

    var session = createSession.get();
    assertEquals("fake-session-A", session.getSessionId());

    var unidentifiedAccessKey = new byte[16];
    Arrays.fill(unidentifiedAccessKey, (byte) 0x55);
    var aciKeys = RegisterAccountKeys.createForTest();
    var pniKeys = RegisterAccountKeys.createForTest();
    var registerAccount =
        session.registerAccount(
            "account password",
            true,
            new RegistrationService.AccountAttributes(
                "recovery password".getBytes(),
                1,
                2,
                "registration lock",
                unidentifiedAccessKey,
                true,
                Set.of("capable"),
                true),
            "push token",
            aciKeys.publicKey,
            pniKeys.publicKey,
            aciKeys.signedPreKey,
            pniKeys.signedPreKey,
            aciKeys.pqLastResortPreKey,
            pniKeys.pqLastResortPreKey);

    var secondRequestAndId = fakeRemote.getNextIncomingRequest().get();
    assertNotNull(secondRequestAndId);
    var secondRequest = secondRequestAndId.getFirst();

    assertEquals("POST", secondRequest.getMethod());
    assertEquals("/v1/registration", secondRequest.getPathAndQuery());

    assertEquals(
        Map.of(
            "content-type",
            "application/json",
            "authorization",
            "Basic " + Base64.encodeToString("+18005550123:account password".getBytes())),
        secondRequest.getHeaders());

    var secondRequestJson =
        (JSONObject) new JSONParser().parse(new String(secondRequest.getBody()));

    assertEquals("fake-session-A", secondRequestJson.get("sessionId"));
    assertEquals(true, secondRequestJson.get("skipDeviceTransfer"));
    assertEquals(
        new JSONParser()
            .parse(
                """
            {
                "recoveryPassword": "cmVjb3ZlcnkgcGFzc3dvcmQ=",
                "registrationId": 1,
                "pniRegistrationId": 2,
                "registrationLock": "registration lock",
                "unidentifiedAccessKey": [ 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85 ],
                "unrestrictedUnidentifiedAccess": true,
                "capabilities": { "capable": true },
                "discoverableByPhoneNumber": true,
                "fetchesMessages": false,
            }
            """),
        secondRequestJson.get("accountAttributes"));

    assertEquals(
        Base64.encodeToString(aciKeys.publicKey.serialize()),
        secondRequestJson.get("aciIdentityKey"));
    assertEquals(
        Base64.encodeToString(pniKeys.publicKey.serialize()),
        secondRequestJson.get("pniIdentityKey"));

    // We don't need to check all the keys, just one of each kind is enough.
    assertEquals(
        Map.of(
            "signature", Base64.encodeToString("EC signature".getBytes()),
            "keyId", 1L,
            "publicKey", Base64.encodeToString(aciKeys.signedPreKey.publicKey().serialize())),
        secondRequestJson.get("aciSignedPreKey"));
    assertEquals(
        Map.of(
            "signature", Base64.encodeToString("KEM signature".getBytes()),
            "keyId", 2L,
            "publicKey", Base64.encodeToString(aciKeys.pqLastResortPreKey.publicKey().serialize())),
        secondRequestJson.get("aciPqLastResortPreKey"));

    fakeRemote.sendResponse(
        secondRequestAndId.getSecond(),
        200,
        "OK",
        new String[] {"content-type: application/json"},
        """
        {
            "uuid": "aabbaabb-5555-6666-8888-111111111111",
            "pni": "ddeeddee-5555-6666-8888-111111111111",
            "number": "+18005550123",
            "storageCapable": true,
            "entitlements": {
                "badges": [{
                    "id": "one",
                    "visible": true,
                    "expirationSeconds": 13
                },{
                    "id": "two",
                    "visible": false,
                    "expirationSeconds": 66666
                }],
                "backup": {
                    "backupLevel": 1569,
                    "expirationSeconds": 987654321
                }
            }
        }
        """
            .getBytes());

    var response = registerAccount.get();
    // We only perform a cursory check here because there is a already a dedicated test for bridging
    // the response.
    assertEquals("aabbaabb-5555-6666-8888-111111111111", response.getAci().toServiceIdString());
    assertEquals("PNI:ddeeddee-5555-6666-8888-111111111111", response.getPni().toServiceIdString());
    assertEquals("+18005550123", response.getNumber());
  }

  private static record RegisterAccountKeys(
      ECPublicKey publicKey,
      SignedPublicPreKey<ECPublicKey> signedPreKey,
      SignedPublicPreKey<KEMPublicKey> pqLastResortPreKey) {
    public static RegisterAccountKeys createForTest() {
      return new RegisterAccountKeys(
          ECKeyPair.generate().getPublicKey(),
          new SignedPublicPreKey<>(
              1, ECKeyPair.generate().getPublicKey(), "EC signature".getBytes()),
          new SignedPublicPreKey<>(
              2,
              KEMKeyPair.generate(KEMKeyType.KYBER_1024).getPublicKey(),
              "KEM signature".getBytes()));
    }
  }
}
