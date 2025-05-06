//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../Native';
import { Aci } from '../Address';
import { PublicKey } from '../EcKeys';
import { Environment, type TokioAsyncContext } from '../net';
import { newNativeHandle } from '../internal';

// For JSDoc references
import { type UnauthenticatedChatConnection } from './Chat';

/**
 * Interface of a local persistent key transparency data store.
 *
 * Contents of the store are opaque to the client and are only supposed to be
 * used by the {@link Client}.
 */
export interface Store {
  getLastDistinguishedTreeHead(): Promise<Buffer | null>;
  setLastDistinguishedTreeHead(bytes: Readonly<Buffer> | null): Promise<void>;

  getAccountData(aci: Aci): Promise<Buffer | null>;
  setAccountData(aci: Aci, bytes: Readonly<Buffer>): Promise<void>;
}

/**
 * Options that are accepted by all {@link Client} APIs.
 *
 * abortSignal, if present, can be used to cancel long-running network IO.
 */
export type Options = { abortSignal?: AbortSignal };

/**
 * ACI descriptor for key transparency requests.
 */
export type AciInfo = { aci: Aci; identityKey: PublicKey };
/**
 * E.164 descriptor for key transparency requests.
 */
export type E164Info = {
  e164: string;
  unidentifiedAccessKey: Readonly<Buffer>;
};

/**
 * Key transparency client request
 *
 */
export type Request = {
  /** ACI and ACI Identity Key for the account. Required. */
  aciInfo: AciInfo;
  /** Unidentified access key associated with the account. Optional. */
  e164Info?: E164Info;
  /* Hash of the username associated with the account. Optional. */
  usernameHash?: Readonly<Buffer>;
};

/**
 * Typed API to access the key transparency subsystem using an existing
 * unauthenticated chat connection.
 *
 * Unlike {@link UnauthenticatedChatConnection}, the client does
 * not export "raw" send/receive APIs, and instead uses them internally to
 * implement high-level key transparency operations.
 *
 * See {@link ClientImpl} for the implementation details.
 *
 * Instances should be obtained by calling {@link UnauthenticatedChatConnection.keyTransparencyClient}
 *
 * Example usage:
 *
 * @example
 * ```ts
 * const network = new Net({
 *   localTestServer: false,
 *   env: Environment.Staging,
 *   userAgent: 'key-transparency-example'
 * });
 *
 * const chat = await network.connectUnauthenticatedChat({
 *   onConnectionInterrupted: (_cause) => {}
 * });
 *
 * const kt = chat.keyTransparencyClient();
 *
 * // Promise fulfillment means the operation succeeded with no further steps required.
 * await kt.search({ aciInfo: { aci: myACI, identityKey: myAciIdentityKey } }, store);
 * ```
 *
 */
export interface Client {
  /**
   * Search for account information in the key transparency tree.
   *
   *
   * @param request - Key transparency client {@link Request}.
   * @param store - Local key transparency storage. It will be queried for both
   * the account data and the latest distinguished tree head before sending the
   * server request and, if the request succeeds, will be updated with the
   * search operation results.
   * @param options - options for the asynchronous operation. Optional.
   *
   * @returns A promise that resolves if the search succeeds and the local state has been updated
   * to reflect the latest changes. If the promise is rejected, the UI should be updated to notify
   * the user of the failure.
   */
  // TODO: document concrete errors
  search(
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ): Promise<void>;

  /**
   * Perform a monitor operation for an account previously searched for.
   *
   * If the monitor request discovers that the client has changed their username
   * or phone number, the search request will be performed instead.
   *
   * @param request - Key transparency client {@link Request}.
   * @param store - Local key transparency storage. It will be queried for both
   * the account data and the latest distinguished tree head before sending the
   * server request and, if the request succeeds, will be updated with the
   * search operation results.
   * @param options - options for the asynchronous operation. Optional.
   *
   * @returns A promise that resolves if the monitor succeeds and the local state has been updated
   * to reflect the latest changes. If the promise is rejected, the UI should be updated to notify
   * the user of the failure.
   */
  // TODO: document concrete errors
  monitor(
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ): Promise<void>;
}

export class ClientImpl implements Client {
  constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly chatService: Native.Wrapper<Native.UnauthenticatedChatConnection>,
    private readonly env: Environment
  ) {}

  async search(
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ): Promise<void> {
    const distinguished = await this.getLatestDistinguished(
      store,
      options ?? {}
    );
    const { abortSignal } = options ?? {};
    const {
      aciInfo: { aci, identityKey: aciIdentityKey },
      e164Info,
      usernameHash,
    } = request;
    const { e164, unidentifiedAccessKey } = e164Info ?? {
      e164: null,
      unidentifiedAccessKey: null,
    };
    const searchResultHandle = await this.asyncContext.makeCancellable(
      abortSignal,
      Native.KeyTransparency_Search(
        this.asyncContext,
        this.env,
        this.chatService,
        aci.getServiceIdFixedWidthBinary(),
        aciIdentityKey,
        e164,
        unidentifiedAccessKey,
        usernameHash ?? null,
        await store.getAccountData(aci),
        distinguished
      )
    );
    const accountData = Native.SearchResult_GetAccountData(
      newNativeHandle(searchResultHandle)
    );
    await store.setAccountData(aci, accountData);
  }

  async monitor(
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ): Promise<void> {
    const distinguished = await this.getLatestDistinguished(
      store,
      options ?? {}
    );
    const { abortSignal } = options ?? {};
    const {
      aciInfo: { aci, identityKey: aciIdentityKey },
      e164Info,
      usernameHash,
    } = request;
    const { e164, unidentifiedAccessKey } = e164Info ?? {
      e164: null,
      unidentifiedAccessKey: null,
    };
    const accountData = await this.asyncContext.makeCancellable(
      abortSignal,
      Native.KeyTransparency_Monitor(
        this.asyncContext,
        this.env,
        this.chatService,
        aci.getServiceIdFixedWidthBinary(),
        aciIdentityKey,
        e164,
        unidentifiedAccessKey,
        usernameHash ?? null,
        await store.getAccountData(aci),
        distinguished
      )
    );
    await store.setAccountData(aci, accountData);
  }

  private async updateDistinguished(
    store: Store,
    { abortSignal }: Readonly<Options>
  ): Promise<Buffer> {
    const bytes = await this.asyncContext.makeCancellable(
      abortSignal,
      Native.KeyTransparency_Distinguished(
        this.asyncContext,
        this.env,
        this.chatService,
        await store.getLastDistinguishedTreeHead()
      )
    );
    await store.setLastDistinguishedTreeHead(bytes);
    return bytes;
  }

  private async getLatestDistinguished(
    store: Store,
    options: Readonly<Options>
  ): Promise<Buffer> {
    return (
      (await store.getLastDistinguishedTreeHead()) ??
      (await this.updateDistinguished(store, options))
    );
  }
}
