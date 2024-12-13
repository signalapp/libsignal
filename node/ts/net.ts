//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../Native';
import { Aci } from './Address';
import {
  AppExpiredError,
  ChatServiceInactive,
  DeviceDelinkedError,
  RateLimitedError,
  LibSignalError,
} from './Errors';
import { ServerMessageAck, Wrapper } from '../Native';
import { Buffer } from 'node:buffer';

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
  /**
   * @deprecated this option is ignored by the server.
   */
  returnAcisWithoutUaks: boolean;
  abortSignal?: AbortSignal;
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

type ConnectionManager = Wrapper<Native.ConnectionManager>;

export function newNativeHandle<T>(handle: T): Wrapper<T> {
  return {
    _nativeHandle: handle,
  };
}

/** Low-level async runtime control, mostly just exported for testing. */
export class TokioAsyncContext {
  readonly _nativeHandle: Native.TokioAsyncContext;

  constructor(handle: Native.TokioAsyncContext) {
    this._nativeHandle = handle;
  }

  makeCancellable<T>(
    abortSignal: AbortSignal | undefined,
    promise: Native.CancellablePromise<T>
  ): Promise<T> {
    if (abortSignal !== undefined) {
      const cancellationToken = promise._cancellationToken;
      const cancel = () => {
        Native.TokioAsyncContext_cancel(this, cancellationToken);
      };

      if (abortSignal.aborted) {
        cancel();
      } else {
        abortSignal.addEventListener('abort', cancel);
      }
    }
    return promise;
  }
}

export class ChatServerMessageAck {
  private promise: Promise<void> | null = null;

  constructor(
    private readonly asyncContext: TokioAsyncContext,
    readonly _nativeHandle: Native.ServerMessageAck
  ) {}

  send(statusCode: number): Promise<void> {
    if (!this.promise) {
      this.promise = Native.ServerMessageAck_SendStatus(
        this.asyncContext,
        this,
        statusCode
      );
    }
    return this.promise;
  }
}

export interface ConnectionEventsListener {
  /**
   * Called when the client gets disconnected from the server.
   *
   * This includes both deliberate disconnects as well as unexpected socket
   * closures. If the closure was not due to a deliberate disconnect, the error
   * will be provided.
   */
  onConnectionInterrupted(cause: LibSignalError | null): void;
}

export interface ChatServiceListener extends ConnectionEventsListener {
  /**
   * Called when the server delivers an incoming message to the client.
   *
   * `timestamp` is in milliseconds.
   *
   * If `ack`'s `send` method is not called, the server will leave this message in the message
   * queue and attempt to deliver it again in the future.
   */
  onIncomingMessage(
    envelope: Buffer,
    timestamp: number,
    ack: ChatServerMessageAck
  ): void;

  /**
   * Called when the server indicates that there are no further messages in the message queue.
   *
   * Note that further messages may still be delivered; this merely indicates that all messages that
   * were in the queue *when the connection was established* have been delivered.
   */
  onQueueEmpty(): void;
}

/**
 * Provides API methods to connect and communicate with the Chat Service.
 * Before sending/receiving requests, a {@link #connect()} method must be called.
 * It's also important to call {@link #disconnect()} method when the instance is no longer needed.
 */
export type ChatService = {
  /**
   * Initiates establishing of the underlying connection to the Chat Service. Once the
   * service is connected, all the requests will be using the established connection. Also, if the
   * connection is lost for any reason other than the call to {@link #disconnect()}, an automatic
   * reconnect attempt will be made.
   *
   * Calling this method will result in starting to accept incoming requests from the Chat Service.
   *
   * @throws {AppExpiredError} if the current app version is too old (as judged by the server).
   * @throws {DeviceDelinkedError} if the current device has been delinked.
   * @throws {RateLimitedError} if the device should wait, then retry.
   * @throws {LibSignalError} with other codes for other failures.
   */
  connect(options?: {
    abortSignal?: AbortSignal;
  }): Promise<Native.ChatServiceDebugInfo>;

  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it will not attempt to automatically reconnect until you call
   * {@link #connect()}.
   *
   * Note: the same instance of `ChatService` can be reused after {@link #disconnect()} was
   * called.
   */
  disconnect(): Promise<void>;

  /**
   * Sends request to the Chat Service.
   *
   * In addition to the response, an object containing debug information about the request flow is
   * returned.
   *
   * @throws {ChatServiceInactive} if you haven't called {@link #connect()} (as a
   * rejection of the promise).
   */
  fetchAndDebug(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ResponseAndDebugInfo>;

  /**
   * Sends request to the Chat Service.
   *
   * @throws {ChatServiceInactive} if you haven't called {@link #connect()} (as a
   * rejection of the promise).
   */
  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse>;
};

/**
 * A connection to the Chat Service.
 *
 * Provides API methods to communicate with the remote service. Make sure to
 * call {@link #disconnect()} when the instance is no longer needed.
 */
export type ChatConnection = {
  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it cannot be used again.
   */
  disconnect(): Promise<void>;

  /**
   * Sends request to the Chat service.
   */
  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse>;

  /**
   * Information about the connection to the Chat service.
   */
  connectionInfo(): ConnectionInfo;
};

export interface ConnectionInfo {
  localPort: number;
  ipVersion: 'IPv4' | 'IPv6';
  toString: () => string;
}

class ConnectionInfoImpl
  implements Wrapper<Native.ChatConnectionInfo>, ConnectionInfo
{
  constructor(public _nativeHandle: Native.ChatConnectionInfo) {}

  public get localPort(): number {
    return Native.ChatConnectionInfo_local_port(this);
  }

  public get ipVersion(): 'IPv4' | 'IPv6' {
    const value = Native.ChatConnectionInfo_ip_version(this);
    switch (value) {
      case 1:
        return 'IPv4';
      case 2:
        return 'IPv6';
      default:
        throw new TypeError(`ip type was unexpectedly ${value}`);
    }
  }

  public toString() : string {
    return Native.ChatConnectionInfo_description(this)
  }
}

export class UnauthenticatedChatConnection implements ChatConnection {
  static async connect(
    asyncContext: TokioAsyncContext,
    connectionManager: ConnectionManager,
    listener: ConnectionEventsListener,
    options?: { abortSignal?: AbortSignal }
  ): Promise<UnauthenticatedChatConnection> {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    const connect = Native.UnauthenticatedChatConnection_connect(
      asyncContext,
      connectionManager
    );
    const chat = await asyncContext.makeCancellable(
      options?.abortSignal,
      connect
    );

    const connection = newNativeHandle(chat);
    Native.UnauthenticatedChatConnection_init_listener(
      connection,
      new WeakListenerWrapper(nativeChatListener)
    );

    return new UnauthenticatedChatConnection(
      asyncContext,
      connection,
      nativeChatListener
    );
  }

  private constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly chatService: Wrapper<Native.UnauthenticatedChatConnection>,
    // Unused except to keep the listener alive since the Rust code only holds a
    // weak reference to the same object.
    private readonly chatListener: Native.ChatListener
  ) {}

  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.UnauthenticatedChatConnection_send(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }

  disconnect(): Promise<void> {
    return Native.UnauthenticatedChatConnection_disconnect(
      this.asyncContext,
      this.chatService
    );
  }

  connectionInfo(): ConnectionInfo {
    return new ConnectionInfoImpl(
      Native.UnauthenticatedChatConnection_info(this.chatService)
    );
  }
}

export class AuthenticatedChatConnection implements ChatConnection {
  static async connect(
    asyncContext: TokioAsyncContext,
    connectionManager: ConnectionManager,
    username: string,
    password: string,
    receiveStories: boolean,
    listener: ChatServiceListener,
    options?: { abortSignal?: AbortSignal }
  ): Promise<AuthenticatedChatConnection> {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    const connect = Native.AuthenticatedChatConnection_connect(
      asyncContext,
      connectionManager,
      username,
      password,
      receiveStories
    );
    const chat = await asyncContext.makeCancellable(
      options?.abortSignal,
      connect
    );
    const connection = newNativeHandle(chat);
    Native.AuthenticatedChatConnection_init_listener(
      connection,
      new WeakListenerWrapper(nativeChatListener)
    );
    return new AuthenticatedChatConnection(
      asyncContext,
      connection,
      nativeChatListener
    );
  }

  private constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly chatService: Wrapper<Native.AuthenticatedChatConnection>,
    // Unused except to keep the listener alive since the Rust code only holds a
    // weak reference to the same object.
    private readonly chatListener: Native.ChatListener
  ) {}

  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.AuthenticatedChatConnection_send(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }

  disconnect(): Promise<void> {
    return Native.AuthenticatedChatConnection_disconnect(
      this.asyncContext,
      this.chatService
    );
  }

  connectionInfo(): ConnectionInfo {
    return new ConnectionInfoImpl(
      Native.AuthenticatedChatConnection_info(this.chatService)
    );
  }
}

/**
 * Holds a {@link Native.ChatListener} by {@link WeakRef} and delegates
 * `ChatListener` calls to it.
 *
 * This lets us avoid passing anything across the bridge that has a normal
 * (strong) reference to the app-side listener. The danger is that the passed-in
 * listener might gain a reference to the JS connection object; that would
 * result in a reference cycle that Node can't clean up because one of the
 * references is through a Rust `Box`.
 *
 * When constructing a connection, calling code should wrap an app-side listener
 * in this type and pass it across the bridge, then hold its own strong
 * reference to the same listener as a field. This ensures that if there is a
 * reference cycle between the connection and app-side listener, that cycle is
 * visible to the Node runtime, while still ensuring the passed-in listener
 * stays alive as long as the connection does.
 */
class WeakListenerWrapper implements Native.ChatListener {
  private listener: WeakRef<Native.ChatListener>;
  constructor(listener: Native.ChatListener) {
    this.listener = new WeakRef(listener);
  }
  _connection_interrupted(reason: Error | null): void {
    this.listener.deref()?._connection_interrupted(reason);
  }
  _incoming_message(
    envelope: Buffer,
    timestamp: number,
    ack: ServerMessageAck
  ): void {
    this.listener.deref()?._incoming_message(envelope, timestamp, ack);
  }
  _queue_empty(): void {
    this.listener.deref()?._queue_empty();
  }
}

/**
 * Provides API methods to connect and communicate with the Chat Service over an authenticated channel.
 */
export class AuthenticatedChatService implements ChatService {
  public readonly chatService: Wrapper<Native.AuthChat>;

  constructor(
    private readonly asyncContext: TokioAsyncContext,
    connectionManager: ConnectionManager,
    username: string,
    password: string,
    receiveStories: boolean,
    listener: ChatServiceListener
  ) {
    this.chatService = newNativeHandle(
      Native.ChatService_new_auth(
        connectionManager,
        username,
        password,
        receiveStories
      )
    );
    const nativeChatListener = {
      _incoming_message(
        envelope: Buffer,
        timestamp: number,
        ack: ServerMessageAck
      ): void {
        listener.onIncomingMessage(
          envelope,
          timestamp,
          new ChatServerMessageAck(asyncContext, ack)
        );
      },
      _queue_empty(): void {
        listener.onQueueEmpty();
      },
      _connection_interrupted(cause: LibSignalError | null): void {
        listener.onConnectionInterrupted(cause);
      },
    };
    Native.ChatService_SetListenerAuth(
      asyncContext,
      this.chatService,
      nativeChatListener
    );
  }

  disconnect(): Promise<void> {
    return Native.ChatService_disconnect_auth(
      this.asyncContext,
      this.chatService
    );
  }

  connect(options?: {
    abortSignal?: AbortSignal;
  }): Promise<Native.ChatServiceDebugInfo> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_connect_auth(this.asyncContext, this.chatService)
    );
  }

  fetchAndDebug(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ResponseAndDebugInfo> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_auth_send_and_debug(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }

  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_auth_send(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }
}

/**
 * Provides API methods to connect and communicate with the Chat Service over an unauthenticated channel.
 */
export class UnauthenticatedChatService implements ChatService {
  public readonly chatService: Wrapper<Native.UnauthChat>;

  constructor(
    private readonly asyncContext: TokioAsyncContext,
    connectionManager: ConnectionManager,
    listener: ConnectionEventsListener
  ) {
    this.chatService = newNativeHandle(
      Native.ChatService_new_unauth(connectionManager)
    );
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    Native.ChatService_SetListenerUnauth(
      asyncContext,
      this.chatService,
      nativeChatListener
    );
  }

  disconnect(): Promise<void> {
    return Native.ChatService_disconnect_unauth(
      this.asyncContext,
      this.chatService
    );
  }

  connect(options?: {
    abortSignal?: AbortSignal;
  }): Promise<Native.ChatServiceDebugInfo> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_connect_unauth(this.asyncContext, this.chatService)
    );
  }

  fetchAndDebug(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ResponseAndDebugInfo> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_unauth_send_and_debug(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }

  fetch(
    chatRequest: ChatRequest,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Native.ChatResponse> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.ChatService_unauth_send(
        this.asyncContext,
        this.chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }
}

function makeNativeChatListener(
  asyncContext: TokioAsyncContext,
  listener: ConnectionEventsListener | ChatServiceListener
): Native.ChatListener {
  if ('onQueueEmpty' in listener) {
    return {
      _incoming_message(
        envelope: Buffer,
        timestamp: number,
        ack: ServerMessageAck
      ): void {
        listener.onIncomingMessage(
          envelope,
          timestamp,
          new ChatServerMessageAck(asyncContext, ack)
        );
      },
      _queue_empty(): void {
        listener.onQueueEmpty();
      },
      _connection_interrupted(cause: Error | null): void {
        listener.onConnectionInterrupted(cause as LibSignalError | null);
      },
    };
  }

  return {
    _incoming_message(
      _envelope: Buffer,
      _timestamp: number,
      _ack: ServerMessageAck
    ): void {
      throw new Error('Event not supported on unauthenticated connection');
    },
    _queue_empty(): void {
      throw new Error('Event not supported on unauthenticated connection');
    },
    _connection_interrupted(cause: LibSignalError | null): void {
      listener.onConnectionInterrupted(cause);
    },
  };
}

export function buildHttpRequest(
  chatRequest: ChatRequest
): Wrapper<Native.HttpRequest> {
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

export type NetConstructorOptions = Readonly<
  | {
      localTestServer?: false;
      env: Environment;
      userAgent: string;
    }
  | {
      localTestServer: true;
      userAgent: string;
      TESTING_localServer_chatPort: number;
      TESTING_localServer_cdsiPort: number;
      TESTING_localServer_svr2Port: number;
      TESTING_localServer_svr3SgxPort: number;
      TESTING_localServer_svr3NitroPort: number;
      TESTING_localServer_svr3Tpm2SnpPort: number;
      TESTING_localServer_rootCertificateDer: Buffer;
    }
>;

export class Net {
  private readonly asyncContext: TokioAsyncContext;
  private readonly connectionManager: ConnectionManager;

  constructor(options: NetConstructorOptions) {
    this.asyncContext = new TokioAsyncContext(Native.TokioAsyncContext_new());

    if (options.localTestServer) {
      this.connectionManager = newNativeHandle(
        Native.TESTING_ConnectionManager_newLocalOverride(
          options.userAgent,
          options.TESTING_localServer_chatPort,
          options.TESTING_localServer_cdsiPort,
          options.TESTING_localServer_svr2Port,
          options.TESTING_localServer_svr3SgxPort,
          options.TESTING_localServer_svr3NitroPort,
          options.TESTING_localServer_svr3Tpm2SnpPort,
          options.TESTING_localServer_rootCertificateDer
        )
      );
    } else {
      this.connectionManager = newNativeHandle(
        Native.ConnectionManager_new(options.env, options.userAgent)
      );
    }
  }

  /**
   * Creates a new instance of {@link AuthenticatedChatService}.
   *
   * Note that created `AuthenticatedChatService` will hold a **non-garbage-collectable** reference to `listener`.
   * If `listener` contains a strong reference to this ChatService (directly or indirectly), both objects will be kept
   * alive even with no other references. If such reference cycle is created, it's the responsibility of the caller
   * to eventually break it (either using a weak reference or by assigning over the strong reference).
   */
  public newAuthenticatedChatService(
    username: string,
    password: string,
    receiveStories: boolean,
    listener: ChatServiceListener
  ): AuthenticatedChatService {
    return new AuthenticatedChatService(
      this.asyncContext,
      this.connectionManager,
      username,
      password,
      receiveStories,
      listener
    );
  }

  /**
   * Creates a new instance of {@link UnauthenticatedChatService}.
   */
  public newUnauthenticatedChatService(
    listener: ConnectionEventsListener
  ): UnauthenticatedChatService {
    return new UnauthenticatedChatService(
      this.asyncContext,
      this.connectionManager,
      listener
    );
  }

  /**
   *
   * Creates a new instance of {@link UnauthenticatedChatConnection}.
   * @param listener the listener for incoming events.
   * @param options additional options to pass through.
   * @param options.abortSignal an {@link AbortSignal} that will cancel the connection attempt.
   * @returns the connected listener, if the connection succeeds.
   */
  public async connectUnauthenticatedChat(
    listener: ConnectionEventsListener,
    options?: { abortSignal?: AbortSignal }
  ): Promise<UnauthenticatedChatConnection> {
    return UnauthenticatedChatConnection.connect(
      this.asyncContext,
      this.connectionManager,
      listener,
      options
    );
  }

  /**
   * Creates a new instance of {@link AuthenticatedChatConnection}.
   */
  public connectAuthenticatedChat(
    username: string,
    password: string,
    receiveStories: boolean,
    listener: ChatServiceListener,
    options?: { abortSignal?: AbortSignal }
  ): Promise<AuthenticatedChatConnection> {
    return AuthenticatedChatConnection.connect(
      this.asyncContext,
      this.connectionManager,
      username,
      password,
      receiveStories,
      listener,
      options
    );
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
   * Enables or disables censorship circumvention for all new connections (until changed).
   *
   * If CC is enabled, *new* connections and services may try additional routes to the Signal
   * servers. Existing connections and services will continue with the setting they were created
   * with. (In particular, changing this setting will not affect any existing
   * {@link ChatService ChatServices}.)
   *
   * CC is off by default.
   */
  public setCensorshipCircumventionEnabled(enabled: boolean): void {
    Native.ConnectionManager_set_censorship_circumvention_enabled(
      this.connectionManager,
      enabled
    );
  }

  /**
   * Sets the proxy host to be used for all new connections (until overridden).
   *
   * Sets a domain name and port to be used to proxy all new outgoing
   * connections. The proxy can be overridden by calling this method again or
   * unset by calling {@link #clearProxy}.
   *
   * Throws if the host or port is structurally invalid, such as a port that doesn't fit in u16.
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

  /**
   * Notifies libsignal that the network has changed.
   *
   * This will lead to, e.g. caches being cleared and cooldowns being reset.
   */
  onNetworkChange(): void {
    Native.ConnectionManager_on_network_change(this.connectionManager);
  }

  async cdsiLookup(
    { username, password }: Readonly<ServiceAuth>,
    {
      e164s,
      acisAndAccessKeys,
      abortSignal,
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

    const lookup = await this.asyncContext.makeCancellable(
      abortSignal,
      Native.CdsiLookup_new(
        this.asyncContext,
        this.connectionManager,
        username,
        password,
        request
      )
    );
    return await this.asyncContext.makeCancellable(
      abortSignal,
      Native.CdsiLookup_complete(this.asyncContext, newNativeHandle(lookup))
    );
  }
}
