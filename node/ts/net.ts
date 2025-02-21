//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../Native';
import { Aci } from './Address';
import { LibSignalError } from './Errors';
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
  useNewConnectLogic?: boolean;
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
  constructor(readonly _nativeHandle: Native.ServerMessageAck) {}

  send(statusCode: number): void {
    Native.ServerMessageAck_SendStatus(this, statusCode);
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

  public toString(): string {
    return Native.ChatConnectionInfo_description(this);
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

  /**
   * Creates a chat connection backed by a fake remote end.
   *
   * @param asyncContext the async runtime to use
   * @param listener the listener to send events to
   * @returns an {@link AuthenticatedChatConnection} and handle for the remote
   * end of the fake connection.
   */
  public static fakeConnect(
    asyncContext: TokioAsyncContext,
    listener: ChatServiceListener
  ): [AuthenticatedChatConnection, Wrapper<Native.FakeChatRemoteEnd>] {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    const fakeChat = newNativeHandle(
      Native.TESTING_FakeChatConnection_Create(
        asyncContext,
        new WeakListenerWrapper(nativeChatListener)
      )
    );

    const chat = newNativeHandle(
      Native.TESTING_FakeChatConnection_TakeAuthenticatedChat(fakeChat)
    );

    return [
      new AuthenticatedChatConnection(asyncContext, chat, nativeChatListener),
      newNativeHandle(Native.TESTING_FakeChatConnection_TakeRemote(fakeChat)),
    ];
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
          new ChatServerMessageAck(ack)
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

/** See {@link Net.setProxy()}. */
export type ProxyOptions = {
  scheme: string;
  host: string;
  port?: number;
  username?: string;
  password?: string;
};

/** The "scheme" for Signal TLS proxies. See {@link Net.setProxy()}. */
export const SIGNAL_TLS_PROXY_SCHEME = 'org.signal.tls';

export class Net {
  private readonly asyncContext: TokioAsyncContext;
  /** Exposed only for testing. */
  readonly _connectionManager: ConnectionManager;

  constructor(options: NetConstructorOptions) {
    this.asyncContext = new TokioAsyncContext(Native.TokioAsyncContext_new());

    if (options.localTestServer) {
      this._connectionManager = newNativeHandle(
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
      this._connectionManager = newNativeHandle(
        Native.ConnectionManager_new(options.env, options.userAgent)
      );
    }
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
      this._connectionManager,
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
      this._connectionManager,
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
      this._connectionManager,
      ipv6Enabled
    );
  }

  /**
   * Enables or disables censorship circumvention for all new connections (until changed).
   *
   * If CC is enabled, *new* connections and services may try additional routes to the Signal
   * servers. Existing connections and services will continue with the setting they were created
   * with. (In particular, changing this setting will not affect any existing
   * {@link ChatConnection ChatConnections}.)
   *
   * CC is off by default.
   */
  public setCensorshipCircumventionEnabled(enabled: boolean): void {
    Native.ConnectionManager_set_censorship_circumvention_enabled(
      this._connectionManager,
      enabled
    );
  }

  /**
   * Sets the proxy host to be used for all new connections (until overridden).
   *
   * Sets a server to be used to proxy all new outgoing connections. The proxy can be overridden by
   * calling this method again or unset by calling {@link #clearProxy}. Omitting the `port` means
   * the default port for the scheme will be used.
   *
   * To specify a Signal transparent TLS proxy, use {@link SIGNAL_TLS_PROXY_SCHEME}, or the
   * overload that takes a separate domain and port number.
   *
   * Throws if the scheme is unsupported or if the provided parameters are invalid for that scheme
   * (e.g. Signal TLS proxies don't support authentication)
   */
  setProxy(options: Readonly<ProxyOptions>): void;
  /**
   * Sets the Signal TLS proxy host to be used for all new connections (until overridden).
   *
   * Sets a domain name and port to be used to proxy all new outgoing connections, using a Signal
   * transparent TLS proxy. The proxy can be overridden by calling this method again or unset by
   * calling {@link #clearProxy}.
   *
   * Throws if the host or port is structurally invalid, such as a port that doesn't fit in u16.
   */
  setProxy(host: string, port?: number): void;
  setProxy(
    hostOrOptions: string | Readonly<ProxyOptions>,
    portOrNothing?: number
  ): void {
    if (typeof hostOrOptions === 'string') {
      // Support <username>@<host> syntax to allow UNENCRYPTED_FOR_TESTING as a marker user.
      // This is not a stable feature of the API and may go away in the future;
      // the Rust layer will reject any other users anyway. But it's convenient for us.
      const [before, after] = hostOrOptions.split('@', 2);
      const [username, domain] = after ? [before, after] : [undefined, before];
      hostOrOptions = {
        scheme: SIGNAL_TLS_PROXY_SCHEME,
        host: domain,
        port: portOrNothing,
        username,
      };
    }
    const { scheme, host, port, username, password } = hostOrOptions;
    try {
      const proxyConfig = newNativeHandle(
        Native.ConnectionProxyConfig_new(
          scheme,
          host,
          // i32::MIN represents "no port provided"; we don't expect anyone to pass that manually.
          port ?? -0x8000_0000,
          username ?? null,
          password ?? null
        )
      );
      Native.ConnectionManager_set_proxy(this._connectionManager, proxyConfig);
    } catch (e) {
      this.setInvalidProxy();
      throw e;
    }
  }

  /**
   * Like {@link #setProxy}, but parses the proxy options from a URL. See there for more
   * information.
   *
   * Takes a string rather than a URL so that an *invalid* string can result in disabling
   * connections until {@link #clearProxy} is called, consistent with other ways {@link #setProxy}
   * might consider its parameters invalid.
   *
   * Throws if the URL contains unnecessary parts (like a query string), or if the resulting options
   * are not supported.
   */
  setProxyFromUrl(urlString: string): void {
    let options: ProxyOptions;
    try {
      options = Net.proxyOptionsFromUrl(urlString);
    } catch (e) {
      // Make sure we set an invalid proxy on error,
      // so no connection can be made until the problem is fixed.
      this.setInvalidProxy();
      throw e;
    }

    this.setProxy(options);
  }

  /**
   * Parses a proxy URL into an options object, suitable for passing to {@link #setProxy}.
   *
   * It is recommended not to call this directly. Instead, use {@link #setProxyFromUrl}, which will
   * treat an invalid URL uniformly with one that is structurally valid but unsupported by
   * libsignal.
   *
   * Throws if the URL is known to not be a valid proxy URL; however it's still possible the
   * resulting options object cannot be used as a proxy.
   */
  static proxyOptionsFromUrl(urlString: string): ProxyOptions {
    const url = new URL(urlString);

    // Check all the parts of the URL.
    // scheme://username:password@hostname:port/path?query#fragment
    const scheme = url.protocol.slice(0, -1);
    // This does not distinguish between "https://proxy.example" and "https://@proxy.example".
    // This could be done by manually checking `url.href`.
    // But until someone complains about it, let's not worry about it.
    const username = url.username != '' ? url.username : undefined;
    const password = url.password != '' ? url.password : undefined;

    const host = url.hostname;
    const port = url.port != '' ? Number.parseInt(url.port, 10) : undefined;

    if (url.pathname != '' && url.pathname != '/') {
      throw new Error('proxy URLs should not have path components');
    }
    if (url.search != '') {
      throw new Error('proxy URLs should not have query components');
    }
    if (url.hash != '') {
      throw new Error('proxy URLs should not have fragment components');
    }

    return { scheme, username, password, host, port };
  }

  /**
   * Refuses to make any new connections until a new proxy configuration is set or
   * {@link #clearProxy} is called.
   *
   * Existing connections will not be affected.
   */
  setInvalidProxy(): void {
    Native.ConnectionManager_set_invalid_proxy(this._connectionManager);
  }

  /**
   * Ensures that future connections will be made directly, not through a proxy.
   *
   * Clears any proxy configuration set via {@link #setProxy} or {@link #setInvalidProxy}. If none
   * was set, calling this method is a no-op.
   */
  clearProxy(): void {
    Native.ConnectionManager_clear_proxy(this._connectionManager);
  }

  /**
   * Notifies libsignal that the network has changed.
   *
   * This will lead to, e.g. caches being cleared and cooldowns being reset.
   */
  onNetworkChange(): void {
    Native.ConnectionManager_on_network_change(this._connectionManager);
  }

  async cdsiLookup(
    { username, password }: Readonly<ServiceAuth>,
    {
      e164s,
      acisAndAccessKeys,
      abortSignal,
      useNewConnectLogic,
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

    const startLookup = useNewConnectLogic
      ? Native.CdsiLookup_new_routes
      : Native.CdsiLookup_new;

    const lookup = await this.asyncContext.makeCancellable(
      abortSignal,
      startLookup(
        this.asyncContext,
        this._connectionManager,
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
