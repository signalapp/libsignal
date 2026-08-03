//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import sinonChai from 'sinon-chai';
import { Buffer } from 'node:buffer';

import * as util from './util.js';
import * as Native from '../Native.js';
import { ErrorCode, LibSignalErrorBase } from '../Errors.js';
import {
  RegisterAccountResponse,
  RegistrationService,
  RegistrationSessionState,
  Svr2CredentialResult,
  TokioAsyncContext,
} from '../net.js';
import { IdentityKeyPair } from '../EcKeys.js';
import { Aci, Pni } from '../Address.js';
import { newNativeHandle } from '../internal.js';

use(chaiAsPromised);
use(sinonChai);

util.initLogger();
config.truncateThreshold = 0;

describe('Registration types', () => {
  describe('registration session conversion', () => {
    const expectedSession: RegistrationSessionState = {
      allowedToRequestCode: true,
      verified: true,
      nextCallSecs: 123,
      nextSmsSecs: 456,
      nextVerificationAttemptSecs: 789,
      requestedInformation: new Set(['pushChallenge']),
    };

    const convertedSession = RegistrationService._convertNativeSessionState(
      newNativeHandle(Native.TESTING_RegistrationSessionInfoConvert())
    );
    expect(convertedSession).to.deep.equal(expectedSession);
  });

  it('marshals signed public pre-key correctly', () => {
    const key = IdentityKeyPair.generate().publicKey;
    const signedPublicPreKey = {
      keyId: 42,
      publicKey: key.serialize(),
      signature: Buffer.from('signature'),
    };
    Native.TESTING_SignedPublicPreKey_CheckBridgesCorrectly(
      key,
      signedPublicPreKey
    );
  });

  it('converts register account response correctly', () => {
    const response = new RegisterAccountResponse(
      Native.TESTING_RegisterAccountResponse_CreateTestValue()
    );
    expect(response.number).to.eq('+18005550123');
    expect(response.aci).to.deep.eq(
      Aci.parseFromServiceIdString('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
    );
    expect(response.pni).to.deep.eq(
      Pni.parseFromServiceIdString('PNI:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')
    );
    expect(response.usernameHash).to.deep.eq(Buffer.from('username-hash'));
    expect(response.usernameLinkHandle).to.deep.eq(
      Uint8Array.from(Array(16).fill(0x55))
    );
    expect(response.storageCapable).to.eq(true);
    expect(response.entitlementBadges).to.deep.eq([
      { id: 'first', visible: true, expirationSeconds: 123456 },
      { id: 'second', visible: false, expirationSeconds: 555 },
    ]);
    expect(response.backupEntitlement).to.deep.eq({
      backupLevel: 123n,
      expirationSeconds: 888888n,
    });
    expect(response.reregistration).to.eq(true);
  });

  it('converts SVR2 credential response correctly', () => {
    const expectedEntries: Map<string, Svr2CredentialResult> = new Map(
      Object.entries({
        'username:pass-match': 'match',
        'username:pass-no-match': 'no-match',
        'username:pass-invalid': 'invalid',
      })
    );
    expect(
      Native.TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert()
    ).deep.eq(expectedEntries);
  });

  expect(() =>
    Native.TESTING_RegistrationService_CreateSessionErrorConvert(
      'InvalidSessionId'
    )
  ).throws(LibSignalErrorBase);

  describe('error conversion', () => {
    const retryLaterCase: [string, object] = [
      'RetryAfter42Seconds',
      {
        code: ErrorCode.RateLimitedError,
        retryAfterSecs: 42,
      },
    ];
    const unknownCase: [string, object] = [
      'Unknown',
      {
        code: ErrorCode.Generic,
        message: 'some message',
      },
    ];
    const timeoutCase: [string, ErrorCode] = ['Timeout', ErrorCode.IoError];
    const serverSideErrorCase: [string, object] = [
      'ServerSideError',
      {
        code: ErrorCode.Generic,
        message: 'server-side error, retryable with backoff',
      },
    ];
    const rateLimitChallengeCase: [string, object] = [
      'PushChallenge',
      {
        code: ErrorCode.RateLimitChallengeError,
        token: 'token',
        options: new Set(['pushChallenge']),
        retryAfterSecs: null,
      },
    ];
    const rateLimitRetryChallengeCase: [string, object] = [
      'PushChallengeRetryAfter42Seconds',
      {
        code: ErrorCode.RateLimitChallengeError,
        token: 'token42',
        options: new Set(['pushChallenge']),
        retryAfterSecs: 42,
      },
    ];
    const cases: Array<{
      operationName: string;
      convertFn: (_: string) => void;
      cases: Array<[string, ErrorCode | object]>;
    }> = [
      {
        operationName: 'CreateSession',
        convertFn: Native.TESTING_RegistrationService_CreateSessionErrorConvert,
        cases: [
          ['InvalidSessionId', ErrorCode.RegistrationSessionIdInvalid],
          retryLaterCase,
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
          rateLimitChallengeCase,
          rateLimitRetryChallengeCase,
        ],
      },
      {
        operationName: 'ResumeSession',
        convertFn: Native.TESTING_RegistrationService_ResumeSessionErrorConvert,
        cases: [
          ['InvalidSessionId', ErrorCode.RegistrationSessionIdInvalid],
          ['SessionNotFound', ErrorCode.RegistrationSessionNotFound],
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
          rateLimitChallengeCase,
          rateLimitRetryChallengeCase,
        ],
      },
      {
        operationName: 'UpdateSession',
        convertFn: Native.TESTING_RegistrationService_UpdateSessionErrorConvert,
        cases: [
          ['Rejected', ErrorCode.RegistrationRequestRejected],
          retryLaterCase,
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
        ],
      },
      {
        operationName: 'RequestVerificationCode',
        convertFn:
          Native.TESTING_RegistrationService_RequestVerificationCodeErrorConvert,
        cases: [
          ['InvalidSessionId', ErrorCode.RegistrationSessionIdInvalid],
          ['SessionNotFound', ErrorCode.RegistrationSessionNotFound],
          [
            'NotReadyForVerification',
            {
              code: ErrorCode.RegistrationSessionNotReadyForVerification,
              sessionState: {
                allowedToRequestCode: false,
                verified: false,
                nextSmsSecs: 3,
                nextCallSecs: 14,
                nextVerificationAttemptSecs: 15,
                requestedInformation: new Set(['captcha']),
              },
            },
          ],
          [
            'NotReadyForVerificationNoSessionState',
            {
              code: ErrorCode.RegistrationSessionNotReadyForVerification,
              sessionState: undefined,
            },
          ],
          [
            'SendFailed',
            {
              code: ErrorCode.RegistrationVerificationSendFailed,
              sessionState: {
                allowedToRequestCode: false,
                verified: false,
                nextSmsSecs: 3,
                nextCallSecs: 14,
                nextVerificationAttemptSecs: 15,
                requestedInformation: new Set(['captcha']),
              },
            },
          ],
          [
            'SendFailedNoSessionState',
            {
              code: ErrorCode.RegistrationVerificationSendFailed,
              sessionState: undefined,
            },
          ],
          [
            'CodeNotDeliverable',
            {
              code: ErrorCode.RegistrationVerificationCodeNotDeliverable,
              reason: 'no reason',
              permanentFailure: true,
            },
          ],
          retryLaterCase,
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
        ],
      },
      {
        operationName: 'SubmitVerification',
        convertFn:
          Native.TESTING_RegistrationService_SubmitVerificationErrorConvert,
        cases: [
          ['InvalidSessionId', ErrorCode.RegistrationSessionIdInvalid],
          ['SessionNotFound', ErrorCode.RegistrationSessionNotFound],
          [
            'NotReadyForVerification',
            {
              code: ErrorCode.RegistrationSessionNotReadyForVerification,
              sessionState: {
                allowedToRequestCode: false,
                verified: false,
                nextSmsSecs: 3,
                nextCallSecs: 14,
                nextVerificationAttemptSecs: 15,
                requestedInformation: new Set(['captcha']),
              },
            },
          ],
          [
            'NotReadyForVerificationNoSessionState',
            {
              code: ErrorCode.RegistrationSessionNotReadyForVerification,
              sessionState: undefined,
            },
          ],
          retryLaterCase,
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
        ],
      },
      {
        operationName: 'CheckSvr2Credentials',
        convertFn:
          Native.TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert,
        cases: [
          ['CredentialsCouldNotBeParsed', ErrorCode.RegistrationRequestInvalid],
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
        ],
      },
      {
        operationName: 'RegisterAccount',
        convertFn:
          Native.TESTING_RegistrationService_RegisterAccountErrorConvert,
        cases: [
          [
            'DeviceTransferIsPossibleButNotSkipped',
            ErrorCode.RegistrationDeviceTransferPossibleNotSkipped,
          ],
          [
            'RegistrationRecoveryVerificationFailed',
            ErrorCode.RegistrationRecoveryVerificationFailed,
          ],
          [
            'RegistrationLockFor50Seconds',
            {
              code: ErrorCode.RegistrationLock,
              timeRemainingSeconds: 50,
              svr2Username: 'user',
              svr2Password: 'pass',
            },
          ],

          retryLaterCase,
          unknownCase,
          timeoutCase,
          serverSideErrorCase,
        ],
      },
    ];

    cases.forEach(({ operationName, convertFn, cases: testCases }) => {
      it(`converts ${operationName} errors`, () => {
        testCases.forEach(([name, expectation]) => {
          expect(convertFn.bind(Native, name))
            .throws(LibSignalErrorBase)
            .to.deep.include(
              expectation instanceof Object
                ? expectation
                : { code: expectation }
            );
        });
      });
    });
  });
});

describe('Registration client', () => {
  describe('with fake chat remote', () => {
    it('can create a new session', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());

      const [createSession, getRemote] = RegistrationService.fakeCreateSession(
        tokio,
        { e164: '+18005550123' }
      );
      const fakeRemote = await getRemote;

      const firstRequest = await fakeRemote.assertReceiveIncomingRequest();

      expect(firstRequest.verb).to.eq('POST');
      expect(firstRequest.path).to.eq('/v1/verification/session');

      fakeRemote.sendReplyTo(firstRequest, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: true,
            verified: false,
            requestedInformation: ['pushChallenge', 'captcha'],
            id: 'fake-session-A',
          })
        ),
      });

      const session = await createSession;
      expect(session.sessionId).to.eq('fake-session-A');
      expect(session.sessionState).property('verified').to.eql(false);
      expect(session.sessionState)
        .property('requestedInformation')
        .to.eql(new Set(['pushChallenge', 'captcha']));

      const requestVerification = session.requestVerification({
        transport: 'voice',
        client: 'libsignal test',
        languages: ['fr-CA'],
      });

      const secondRequest = await fakeRemote.assertReceiveIncomingRequest();

      expect(secondRequest.verb).to.eq('POST');
      expect(secondRequest.path).to.eq(
        '/v1/verification/session/fake-session-A/code'
      );
      expect(new TextDecoder().decode(secondRequest.body)).to.eq(
        '{"transport":"voice","client":"libsignal test"}'
      );
      expect(secondRequest.headers).to.deep.eq(
        new Map([
          ['content-type', 'application/json'],
          ['accept-language', 'fr-CA'],
        ])
      );

      fakeRemote.sendReplyTo(secondRequest, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: true,
            verified: false,
            requestedInformation: ['pushChallenge', 'captcha'],
            id: 'fake-session-A',
          })
        ),
      });

      await requestVerification;
    });

    it('refreshes cached session state from failed requests', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());

      const [createSession, getRemote] = RegistrationService.fakeCreateSession(
        tokio,
        { e164: '+18005550123' }
      );
      const fakeRemote = await getRemote;

      const createRequest = await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(createRequest, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: true,
            verified: false,
            requestedInformation: ['pushChallenge'],
            id: 'fake-session-A',
          })
        ),
      });
      const session = await createSession;

      // A failed requestVerification whose body carries updated session state
      // should refresh the service's cached sessionState across the bridge,
      // even though the call rejects.
      const requestVerification = session.requestVerification({
        transport: 'voice',
        client: 'libsignal test',
        languages: ['fr-CA'],
      });
      const sendCodeRequest = await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(sendCodeRequest, {
        status: 418,
        message: 'Send failed',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: false,
            verified: false,
            nextSms: 42,
            requestedInformation: ['captcha'],
            id: 'fake-session-A',
          })
        ),
      });
      await expect(requestVerification).to.be.rejected;
      expect(session.sessionState).to.deep.eq({
        allowedToRequestCode: false,
        verified: false,
        nextSmsSecs: 42,
        nextCallSecs: undefined,
        nextVerificationAttemptSecs: undefined,
        requestedInformation: new Set(['captcha']),
      });

      // Same for a failed verifySession (submit code).
      const verifySession = session.verifySession('123456');
      const submitCodeRequest = await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(submitCodeRequest, {
        status: 409,
        message: 'Not ready',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: true,
            verified: false,
            nextVerificationAttempt: 37,
            requestedInformation: [],
            id: 'fake-session-A',
          })
        ),
      });
      await expect(verifySession).to.be.rejected;
      expect(session.sessionState).to.deep.eq({
        allowedToRequestCode: true,
        verified: false,
        nextSmsSecs: undefined,
        nextCallSecs: undefined,
        nextVerificationAttemptSecs: 37,
        requestedInformation: new Set(),
      });

      // A 429 (rate limited) response also carries session state in its body,
      // but comes back as a RateLimitedError rather than a typed error. The
      // cached session state is still refreshed.
      const rateLimited = session.requestVerification({
        transport: 'voice',
        client: 'libsignal test',
        languages: ['fr-CA'],
      });
      const rateLimitedRequest =
        await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(rateLimitedRequest, {
        status: 429,
        message: 'Too many requests',
        headers: ['content-type: application/json', 'retry-after: 60'],
        body: Buffer.from(
          JSON.stringify({
            allowedToRequestCode: true,
            verified: false,
            nextCall: 99,
            requestedInformation: [],
            id: 'fake-session-A',
          })
        ),
      });
      await expect(rateLimited)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.RateLimitedError);
      expect(session.sessionState).to.deep.eq({
        allowedToRequestCode: true,
        verified: false,
        nextSmsSecs: undefined,
        nextCallSecs: 99,
        nextVerificationAttemptSecs: undefined,
        requestedInformation: new Set(),
      });
    });
  });
});
