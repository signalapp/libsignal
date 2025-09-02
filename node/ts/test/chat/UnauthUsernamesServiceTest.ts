//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, config, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as Native from '../../../Native';
import * as util from '../util';
import { TokioAsyncContext, UnauthUsernamesService } from '../../net';
import { connectUnauth } from './ServiceTestUtils';
import { InternalRequest } from '../NetTest';
import { newNativeHandle } from '../../internal';
import { ErrorCode, LibSignalErrorBase } from '../../Errors';
import { Aci } from '../../Address';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthUsernamesService', () => {
  it('can look up hashes', async () => {
    const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

    const hash = Uint8Array.of(1, 2, 3, 4);
    const responseFuture = chat.lookUpUsernameHash({ hash });

    const rawRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        tokio,
        fakeRemote
      );
    assert(rawRequest !== null);
    const request = new InternalRequest(rawRequest);
    expect(request.verb).to.eq('GET');
    expect(request.path).to.eq(
      `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
    );

    const uuid = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(
      fakeRemote,
      newNativeHandle(
        Native.TESTING_FakeChatResponse_Create(
          request.requestId,
          200,
          'OK',
          ['content-type: application/json'],
          Buffer.from(
            JSON.stringify({
              uuid,
            })
          )
        )
      )
    );

    const responseFromServer = await responseFuture;
    assert(responseFromServer !== null);
    assert(Aci.fromUuid(uuid).isEqual(responseFromServer));
  });

  it('can look up unknown hashes', async () => {
    const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

    const hash = Uint8Array.of(1, 2, 3, 4);
    const responseFuture = chat.lookUpUsernameHash({ hash });

    const rawRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        tokio,
        fakeRemote
      );
    assert(rawRequest !== null);
    const request = new InternalRequest(rawRequest);
    expect(request.verb).to.eq('GET');
    expect(request.path).to.eq(
      `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
    );

    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(
      fakeRemote,
      newNativeHandle(
        Native.TESTING_FakeChatResponse_Create(
          request.requestId,
          404,
          'Not Found',
          [],
          Buffer.of()
        )
      )
    );

    const responseFromServer = await responseFuture;
    assert.isNull(responseFromServer);
  });

  it('can handle challenge errors', async () => {
    const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

    const hash = Uint8Array.of(1, 2, 3, 4);
    const responseFuture = chat.lookUpUsernameHash({ hash });

    const rawRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        tokio,
        fakeRemote
      );
    assert(rawRequest !== null);
    const request = new InternalRequest(rawRequest);
    expect(request.verb).to.eq('GET');
    expect(request.path).to.eq(
      `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
    );

    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(
      fakeRemote,
      newNativeHandle(
        Native.TESTING_FakeChatResponse_Create(
          request.requestId,
          428,
          'Precondition Required',
          ['content-type: application/json'],
          Buffer.from(
            JSON.stringify({
              token: 'not-legal-tender',
              options: ['pushChallenge'],
            })
          )
        )
      )
    );

    await expect(responseFuture)
      .to.eventually.be.rejectedWith(LibSignalErrorBase)
      .and.deep.include({
        code: ErrorCode.RateLimitChallengeError,
        token: 'not-legal-tender',
        options: new Set(['pushChallenge']),
      });
  });

  it('can handle server errors', async () => {
    const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

    const hash = Uint8Array.of(1, 2, 3, 4);
    const responseFuture = chat.lookUpUsernameHash({ hash });

    const rawRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        tokio,
        fakeRemote
      );
    assert(rawRequest !== null);
    const request = new InternalRequest(rawRequest);
    expect(request.verb).to.eq('GET');
    expect(request.path).to.eq(
      `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
    );

    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(
      fakeRemote,
      newNativeHandle(
        Native.TESTING_FakeChatResponse_Create(
          request.requestId,
          500,
          'Internal Server Error',
          [],
          Buffer.of()
        )
      )
    );

    await expect(responseFuture)
      .to.eventually.be.rejectedWith(LibSignalErrorBase)
      .and.deep.include({
        code: ErrorCode.IoError,
      });
  });
});
