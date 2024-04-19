//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../Native';
import { Aci } from './Address';
import {
  IoError,
  SvrDataMissingError,
  SvrRestoreFailedError,
  SvrRequestFailedError,
  ChatServiceInactive,
} from './Errors';
import { Wrapper } from '../Native';

const DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS = 5000;

// This must match the libsignal-bridge Rust enum of the same name.
export enum Environment {
  Staging = 0,
  Production = 1,
}

export type ServiceAuth = {
  username: string;
  password: string;
};

export type CDSRequestOptionsType = {
  e164s: Array<string>;
  acisAndAccessKeys: Array<{ aci: string; accessKey: string }>;
  returnAcisWithoutUaks: boolean;
};

export type CDSResponseEntryType<Aci, Pni> = {
  aci: Aci | undefined;
  pni: Pni | undefined;
};

export type CDSResponseEntries<Aci, Pni> = Map<
  string,
  CDSResponseEntryType<Aci, Pni>
>;

export interface CDSResponseType<Aci, Pni> {
  entries: CDSResponseEntries<Aci, Pni>;
  debugPermitsUsed: number;
}

export type ChatRequest = Readonly<{
  verb: string;
  path: string;
  headers: ReadonlyArray<[string, string]>;
  body?: Uint8Array;
  timeoutMillis?: number;
}>;

type TokioAsyncContext = Wrapper<Native.TokioAsyncContext>;

type ConnectionManager = Wrapper<Native.ConnectionManager>;

function newNativeHandle<T>(handle: T): Wrapper<T> {
  return {
    _nativeHandle: handle,
  };
}

/**
 * Provides API methods to connect and communicate with the Chat Service.
 * Before using either authenticated or unauthenticated channels,
 * a corresponding `connect*` method must be called.
 * It's also important to call {@link #disconnect()} method when the instance is no longer needed.
 */
export class ChatService {
  private readonly chatService: Wrapper<Native.Chat>;

  constructor(
    private readonly asyncContext: TokioAsyncContext,
    connectionManager: ConnectionManager
  ) {
    this.chatService = newNativeHandle(
      Native.ChatService_new(connectionManager, '', '')
    );
  }

  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it will not attempt to automatically reconnect until you call
   * {@link #connectAuthenticated()} and/or {@link #connectUnauthenticated()}.
   *
   * Note: the same instance of `ChatService` can be reused after `disconnect()` was
   * called.
   */
  async disconnect(): Promise<void> {
    await Native.ChatService_disconnect(this.asyncContext, this.chatService);
  }

  /**
   * Initiates establishing of the underlying unauthenticated connection to the Chat Service. Once
   * the service is connected, all the requests will be using the established connection. Also, if
   * the connection is lost for any reason other than the call to {@link #disconnect()}, an
   * automatic reconnect attempt will be made.
   */
  async connectUnauthenticated(): Promise<Native.ChatServiceDebugInfo> {
    return await Native.ChatService_connect_unauth(
      this.asyncContext,
      this.chatService
    );
  }

  /**
   * Initiates establishing of the underlying authenticated connection to the Chat Service. Once the
   * service is connected, all the requests will be using the established connection. Also, if the
   * connection is lost for any reason other than the call to {@link #disconnect()}, an automatic
   * reconnect attempt will be made.
   *
   * Calling this method will result in starting to accept incoming requests from the Chat Service.
   */
  async connectAuthenticated(): Promise<Native.ChatServiceDebugInfo> {
    return await Native.ChatService_connect_auth(
      this.asyncContext,
      this.chatService
    );
  }

  /**
   * Sends request to the Chat Service over an unauthenticated channel.
   *
   * In addition to the response, an object containing debug information about the request flow is
   * returned.
   *
   * @throws {ChatServiceInactive} if you haven't called {@link #connectUnauthenticated()}.
   */
  async unauthenticatedFetchAndDebug(
    chatRequest: ChatRequest
  ): Promise<Native.ResponseAndDebugInfo> {
    return await Native.ChatService_unauth_send_and_debug(
      this.asyncContext,
      this.chatService,
      ChatService.buildHttpRequest(chatRequest),
      chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
    );
  }

  /**
   * Sends request to the Chat Service over an unauthenticated channel.
   *
   * @throws {ChatServiceInactive} if you haven't called {@link #connectUnauthenticated()}.
   */
  async unauthenticatedFetch(
    chatRequest: ChatRequest
  ): Promise<Native.ChatResponse> {
    return await Native.ChatService_unauth_send(
      this.asyncContext,
      this.chatService,
      ChatService.buildHttpRequest(chatRequest),
      chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
    );
  }

  static buildHttpRequest(chatRequest: ChatRequest): {
    _nativeHandle: Native.HttpRequest;
  } {
    const { verb, path, body, headers } = chatRequest;
    const bodyBuffer: Buffer | null =
      body !== undefined ? Buffer.from(body) : null;
    const httpRequest = {
      _nativeHandle: Native.HttpRequest_new(verb, path, bodyBuffer),
    };
    headers.forEach((header) => {
      const [name, value] = header;
      Native.HttpRequest_add_header(httpRequest, name, value);
    });
    return httpRequest;
  }
}

export class Net {
  private readonly asyncContext: TokioAsyncContext;
  private readonly connectionManager: ConnectionManager;

  /**
   * Instance of the {@link Svr3Client} to access SVR3.
   */
  svr3: Svr3Client;

  constructor(env: Environment) {
    this.asyncContext = newNativeHandle(Native.TokioAsyncContext_new());
    this.connectionManager = newNativeHandle(Native.ConnectionManager_new(env));
    this.svr3 = new Svr3ClientImpl(this.asyncContext, this.connectionManager);
  }

  /**
   * Creates a new instance of {@link ChatService}.
   */
  public newChatService(): ChatService {
    return new ChatService(this.asyncContext, this.connectionManager);
  }

  /**
   * Enables/disables IPv6 for all new connections (until changed).
   *
   * The flag is `true` by default.
   */
  public setIpv6Enabled(ipv6Enabled: boolean): void {
    Native.ConnectionManager_set_ipv6_enabled(
      this.connectionManager,
      ipv6Enabled
    );
  }

  /**
   * Sets the proxy host to be used for all new connections (until overridden).
   *
   * Sets a domain name and port to be used to proxy all new outgoing
   * connections. The proxy can be overridden by calling this method again or
   * unset by calling {@link #clearProxy}.
   */
  setProxy(host: string, port: number): void {
    Native.ConnectionManager_set_proxy(this.connectionManager, host, port);
  }

  /**
   * Ensures that future connections will be made directly, not through a proxy.
   *
   * Clears any proxy configuration set via {@link #setProxy}. If none was set, calling this
   * method is a no-op.
   */
  clearProxy(): void {
    Native.ConnectionManager_clear_proxy(this.connectionManager);
  }

  async cdsiLookup(
    { username, password }: Readonly<ServiceAuth>,
    {
      e164s,
      acisAndAccessKeys,
      returnAcisWithoutUaks,
    }: ReadonlyDeep<CDSRequestOptionsType>
  ): Promise<CDSResponseType<string, string>> {
    const request = newNativeHandle(Native.LookupRequest_new());
    e164s.forEach((e164) => {
      Native.LookupRequest_addE164(request, e164);
    });

    acisAndAccessKeys.forEach(({ aci: aciStr, accessKey: accessKeyStr }) => {
      Native.LookupRequest_addAciAndAccessKey(
        request,
        Aci.parseFromServiceIdString(aciStr).getServiceIdFixedWidthBinary(),
        Buffer.from(accessKeyStr, 'base64')
      );
    });

    Native.LookupRequest_setReturnAcisWithoutUaks(
      request,
      returnAcisWithoutUaks
    );

    const lookup = await Native.CdsiLookup_new(
      this.asyncContext,
      this.connectionManager,
      username,
      password,
      request
    );

    return await Native.CdsiLookup_complete(
      this.asyncContext,
      newNativeHandle(lookup)
    );
  }
}

/**
 * This interface provides functionality for communicating with SVR3
 *
 * Its instance can be obtained from an {@link Net#svr3} property
 * of the {@link Net} class.
 *
 * Example usage:
 *
 * @example
 * ```ts
 * import { Environment, Net } from '../net';
 * // Obtain an instance
 * const SVR3 = new Net(Environment.Staging).svr3;
 * // Instantiate ServiceAuth with the username and password obtained from the Chat Server.
 * const auth = { username: USERNAME, password: ENCLAVE_PASSWORD };
 * // Store a value in SVR3. Here 10 is the number of permitted restore attempts.
 * const shareSet = await SVR3.backup(SECRET_TO_BE_STORED, PASSWORD, 10, auth);
 * const restoredSecret = await SVR3.restore( PASSWORD, shareSet, auth);
 * ```
 */
export interface Svr3Client {
  /**
   * Backup a secret to SVR3.
   *
   * Error messages are expected to be log-safe and not contain any sensitive
   *   data.
   *
   * @param what - The secret to be stored. Must be 32 bytes long.
   * @param password - User-provided password that will be used to derive the
   * encryption key for the secret.
   * @param maxTries - Number of times the secret will be allowed to be guessed.
   * Each call to {@link Svr3Client#restore} that has reached the server will
   * decrement the counter. Must be positive.
   * @param auth - An instance of {@link ServiceAuth} containing the username
   * and password obtained from the Chat Server. The password is an OTP which is
   * generally good for about 15 minutes, therefore it can be reused for the
   * subsequent calls to either backup or restore that are not too far apart in
   * time.
   * @returns A `Promise` which--when awaited--will return a byte array with a
   * serialized masked share set. It is supposed to be an opaque blob for the
   * clients and therefore no assumptions should be made about its contents.
   * This byte array should be stored by the clients and used to restore the
   * secret along with the password. Please note that masked share set does not
   * have to be treated as secret.
   *
   * The returned `Promise` can also fail due to the network issues (including a
   * connection timeout), problems establishing the Noise connection to the
   * enclaves, or invalid arguments' values. {@link IoError} errors can, in
   * general, be retried, although there is already a retry-with-backoff
   * mechanism inside libsignal used to connect to the SVR3 servers. Other
   * exceptions are caused by the bad input or data missing on the server. They
   * are therefore non-actionable and are guaranteed to be thrown again when
   * retried.
   */
  backup(
    what: Buffer,
    password: string,
    maxTries: number,
    auth: Readonly<ServiceAuth>
  ): Promise<Buffer>;

  /**
   * Restore a secret from SVR3.
   *
   * Error messages are expected to be log-safe and not contain any sensitive
   * data.
   *
   * @param password - User-provided password that will be used to derive the
   * decryption key for the secret.
   * @param shareSet - a serialized masked share set returned by a call to
   * {@link Svr3Client#backup}.
   * @param auth - An instance of {@link ServiceAuth} containing the username
   * and password obtained from the Chat Server. The password is an OTP which is
   * generally good for about 15 minutes, therefore it can be reused for the
   * subsequent calls to either backup or restore that are not too far apart in
   * time.
   * @returns A `Promise` which--when awaited--will return a byte array with the
   * restored secret.
   *
   * The returned `Promise` can also fail due to the network issues (including
   * the connection timeout), problems establishing the Noise connection to the
   * enclaves, or invalid arguments' values. {@link IoError} errors can, in
   * general, be retried, although there is already a retry-with-backoff
   * mechanism inside libsignal used to connect to the SVR3 servers. Other
   * exceptions are caused by the bad input or data missing on the server. They
   * are therefore non-actionable and are guaranteed to be thrown again when
   * retried.
   *
   * - {@link SvrDataMissingError} is returned when the maximum restore attempts
   * number has been exceeded or if the value has never been backed up.
   * - {@link SvrRestoreFailedError} is returned when the combination of the
   * password and masked share set does not result in successful restoration
   * of the secret.
   * - {@link SvrRequestFailedError} is returned when the de-serialization of a
   * masked share set fails, or when the server requests fail for reasons
   * other than "maximum attempts exceeded".
   */
  restore(
    password: string,
    shareSet: Buffer,
    auth: Readonly<ServiceAuth>
  ): Promise<Buffer>;
}

class Svr3ClientImpl implements Svr3Client {
  constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly connectionManager: ConnectionManager
  ) {}

  async backup(
    what: Buffer,
    password: string,
    maxTries: number,
    auth: Readonly<ServiceAuth>
  ): Promise<Buffer> {
    return Native.Svr3Backup(
      this.asyncContext,
      this.connectionManager,
      what,
      password,
      maxTries,
      auth.username,
      auth.password
    );
  }

  async restore(
    password: string,
    shareSet: Buffer,
    auth: Readonly<ServiceAuth>
  ): Promise<Buffer> {
    return Native.Svr3Restore(
      this.asyncContext,
      this.connectionManager,
      password,
      shareSet,
      auth.username,
      auth.password
    );
  }
}
