//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { TokioAsyncContext } from '../net.js';
import * as Native from '../Native.js';
import { newNativeHandle } from '../internal.js';
import { FakeChatRemoteEnd } from '../Native.js';

import assert from 'node:assert';

export class InternalRequest implements Native.Wrapper<Native.HttpRequest> {
  readonly _nativeHandle: Native.HttpRequest;
  readonly requestId: bigint;

  constructor([nativeHandle, requestId]: [Native.HttpRequest, bigint]) {
    this._nativeHandle = nativeHandle;
    this.requestId = requestId;
  }

  public get verb(): string {
    return Native.TESTING_ChatRequestGetMethod(this);
  }

  public get path(): string {
    return Native.TESTING_ChatRequestGetPath(this);
  }

  public get headers(): Map<string, string> {
    const names = Native.TESTING_ChatRequestGetHeaderNames(this);
    return new Map(
      names.map((name) => {
        return [name, Native.TESTING_ChatRequestGetHeaderValue(this, name)];
      })
    );
  }

  public get body(): Uint8Array {
    return Native.TESTING_ChatRequestGetBody(this);
  }
}

export type ServerResponse = {
  id: bigint;
  status: number;
  message?: string;
  headers?: string[];
  body?: Uint8Array;
};

export class FakeChatRemote {
  constructor(
    private asyncContext: TokioAsyncContext,
    readonly _nativeHandle: FakeChatRemoteEnd
  ) {}

  public async receiveIncomingRequest(): Promise<InternalRequest | null> {
    const nativeRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        this.asyncContext,
        this
      );
    if (nativeRequest === null) {
      return null;
    }
    return new InternalRequest(nativeRequest);
  }

  public async assertReceiveIncomingRequest(): Promise<InternalRequest> {
    const request = await this.receiveIncomingRequest();
    assert(request !== null, 'Cannot reply to the request that is null');
    return request;
  }

  public sendReplyTo(
    request: InternalRequest,
    response: Omit<ServerResponse, 'id'>
  ): void {
    const fullResponse = { id: request.requestId, ...response };
    this.sendServerResponse(fullResponse);
  }

  public sendServerResponse(response: ServerResponse): void {
    const message = response.message ?? '';
    const headers = response.headers ?? [];
    const body = response.body ?? null;

    const nativeResponse = newNativeHandle(
      Native.TESTING_FakeChatResponse_Create(
        response.id,
        response.status,
        message,
        headers,
        body
      )
    );
    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(this, nativeResponse);
  }

  public sendRawServerResponse(bytes: Uint8Array): void {
    Native.TESTING_FakeChatRemoteEnd_SendRawServerResponse(this, bytes);
  }

  public sendRawServerRequest(bytes: Uint8Array): void {
    Native.TESTING_FakeChatRemoteEnd_SendRawServerRequest(this, bytes);
  }

  public injectConnectionInterrupted(): void {
    Native.TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(this);
  }
}
