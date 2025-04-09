//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../Native';
import { Buffer } from 'node:buffer';
import { cdsiLookup, CDSRequestOptionsType, CDSResponseType } from './net/CDSI';
import {
  ChatConnection,
  ConnectionEventsListener,
  UnauthenticatedChatConnection,
  AuthenticatedChatConnection,
  ChatServiceListener,
} from './net/Chat';
import { RegistrationService } from './net/Registration';
import { BridgedStringMap } from './internal';
export * from './net/CDSI';
export * from './net/Chat';
export * from './net/Registration';

// This must match the libsignal-bridge Rust enum of the same name.
export enum Environment {
  Staging = 0,
  Production = 1,
}

export type ServiceAuth = {
  username: string;
  password: string;
};

export type ChatRequest = Readonly<{
  verb: string;
  path: string;
  headers: ReadonlyArray<[string, string]>;
  body?: Uint8Array;
  timeoutMillis?: number;
}>;

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

export function newNativeHandle<T>(handle: T): Native.Wrapper<T> {
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

export type NetConstructorOptions = Readonly<
  | {
      localTestServer?: false;
      env: Environment;
      userAgent: string;
      remoteConfig?: Map<string, string>;
    }
  | {
      localTestServer: true;
      userAgent: string;
      TESTING_localServer_chatPort: number;
      TESTING_localServer_cdsiPort: number;
      TESTING_localServer_svr2Port: number;
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
          options.TESTING_localServer_rootCertificateDer
        )
      );
    } else {
      this._connectionManager = newNativeHandle(
        Native.ConnectionManager_new(
          options.env,
          options.userAgent,
          new BridgedStringMap(
            options.remoteConfig || new Map<string, string>()
          )
        )
      );
    }
  }

  /**
   * Starts the process of connecting to the chat server.
   *
   * If this completes successfully, the next call to {@link #connectAuthenticatedChat} may be able
   * to finish more quickly. If it's incomplete or produces an error, such a call will start from
   * scratch as usual. Only one preconnect is recorded, so there's no point in calling this more
   * than once.
   *
   * @param options additional options to pass through.
   * @param options.abortSignal an {@link AbortSignal} that will cancel the connection attempt.
   */
  public preconnectChat(options?: {
    abortSignal?: AbortSignal;
  }): Promise<void> {
    return this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.AuthenticatedChatConnection_preconnect(
        this.asyncContext,
        this._connectionManager
      )
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

  public async resumeRegistrationSession({
    sessionId,
    e164,
    connectionTimeoutMillis,
  }: {
    sessionId: string;
    e164: string;
    connectionTimeoutMillis?: number;
  }): Promise<RegistrationService> {
    return RegistrationService.resumeSession(
      {
        connectionManager: this._connectionManager,
        tokioAsyncContext: this.asyncContext,
        connectionTimeoutMillis: connectionTimeoutMillis,
      },
      { sessionId, e164 }
    );
  }

  public async createRegistrationSession({
    e164,
    connectionTimeoutMillis,
  }: {
    e164: string;
    connectionTimeoutMillis?: number;
  }): Promise<RegistrationService> {
    return RegistrationService.createSession(
      {
        connectionManager: this._connectionManager,
        tokioAsyncContext: this.asyncContext,
        connectionTimeoutMillis: connectionTimeoutMillis,
      },
      { e164 }
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

  /** Updates the remote config settings used by libsignal. */
  setRemoteConfig(remoteConfig: Map<string, string>): void {
    Native.ConnectionManager_set_remote_config(
      this._connectionManager,
      new BridgedStringMap(remoteConfig)
    );
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
    auth: Readonly<ServiceAuth>,
    options: ReadonlyDeep<CDSRequestOptionsType>
  ): Promise<CDSResponseType<string, string>> {
    return cdsiLookup(
      {
        asyncContext: this.asyncContext,
        connectionManager: this._connectionManager,
      },
      auth,
      options
    );
  }
}
