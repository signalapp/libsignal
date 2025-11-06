//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from './Native.js';
import {
  cdsiLookup,
  CDSRequestOptionsType,
  CDSResponseType,
} from './net/CDSI.js';
import {
  ChatConnection,
  ConnectionEventsListener,
  UnauthenticatedChatConnection,
  AuthenticatedChatConnection,
  ChatServiceListener,
} from './net/Chat.js';
import { RegistrationService } from './net/Registration.js';
import { SvrB } from './net/SvrB.js';
import { BridgedStringMap, newNativeHandle } from './internal.js';
export * from './net/CDSI.js';
export * from './net/Chat.js';
export * from './net/chat/UnauthMessagesService.js';
export * from './net/chat/UnauthUsernamesService.js';
export * from './net/Registration.js';
export * from './net/SvrB.js';

// This must match the libsignal-bridge Rust enum of the same name.
export enum Environment {
  Staging = 0,
  Production = 1,
}

/**
 * Build variant for remote config key selection.
 *
 * This must match the libsignal-bridge Rust enum of the same name.
 *
 * - `Production`: Use for release builds. Only uses base remote config keys without suffixes.
 * - `Beta`: Use for all other builds (nightly, alpha, internal, public betas). Prefers
 *   keys with a `.beta` suffix, falling back to base keys if the suffixed key is not present.
 */
export enum BuildVariant {
  Production = 0,
  Beta = 1,
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
      buildVariant?: BuildVariant;
    }
  | {
      localTestServer: true;
      userAgent: string;
      TESTING_localServer_chatPort: number;
      TESTING_localServer_cdsiPort: number;
      TESTING_localServer_svr2Port: number;
      TESTING_localServer_svrBPort: number;
      TESTING_localServer_rootCertificateDer: Uint8Array;
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

type WithSuffix<Keys extends readonly string[], Suffix extends string> = {
  [Key in keyof Keys]: `${Keys[Key]}.${Suffix}`;
};

function withSuffix<Keys extends readonly string[], Suffix extends string>(
  keys: Keys,
  suffix: Suffix
): WithSuffix<Keys, Suffix> {
  return keys.map((key) => `${key}.${suffix}`) as WithSuffix<Keys, Suffix>;
}

const BETA_REMOTE_CONFIG_KEYS = withSuffix(Native.NetRemoteConfigKeys, 'beta');
// By convention suffix-less keys mean ".prod". These keys predate convention.
// TODO: Remove this line once all the non-conventional keys have been removed.
const PROD_REMOTE_CONFIG_KEYS = ['chatPermessageDeflate.prod'] as const;

export const REMOTE_CONFIG_KEYS = [
  ...Native.NetRemoteConfigKeys,
  ...BETA_REMOTE_CONFIG_KEYS,
  ...PROD_REMOTE_CONFIG_KEYS,
] as const;

export class Net {
  private readonly asyncContext: TokioAsyncContext;
  /** Exposed only for testing. */
  readonly _connectionManager: ConnectionManager;

  constructor(private readonly options: NetConstructorOptions) {
    this.asyncContext = new TokioAsyncContext(Native.TokioAsyncContext_new());

    if (options.localTestServer) {
      this._connectionManager = newNativeHandle(
        Native.TESTING_ConnectionManager_newLocalOverride(
          options.userAgent,
          options.TESTING_localServer_chatPort,
          options.TESTING_localServer_cdsiPort,
          options.TESTING_localServer_svr2Port,
          options.TESTING_localServer_svrBPort,
          options.TESTING_localServer_rootCertificateDer
        )
      );
    } else {
      const {
        env,
        userAgent,
        remoteConfig = new Map<string, string>(),
        buildVariant = BuildVariant.Production,
      } = options;
      this._connectionManager = newNativeHandle(
        Native.ConnectionManager_new(
          env,
          userAgent,
          new BridgedStringMap(remoteConfig),
          buildVariant
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
   * Creates a new instance of {@link UnauthenticatedChatConnection}.
   *
   * @param listener the listener for incoming events.
   * @param options additional options to pass through.
   * @param options.languages If provided, a list of languages in Accept-Language syntax to apply
   * to all requests made on this connection. Note that "quality weighting" can be left out; the
   * Signal server will always consider the list to be in priority order.
   * @param options.abortSignal an {@link AbortSignal} that will cancel the connection attempt.
   */
  public async connectUnauthenticatedChat(
    listener: ConnectionEventsListener,
    options?: { languages?: string[]; abortSignal?: AbortSignal }
  ): Promise<UnauthenticatedChatConnection> {
    const env = this.options.localTestServer ? undefined : this.options.env;
    return UnauthenticatedChatConnection.connect(
      this.asyncContext,
      this._connectionManager,
      listener,
      env,
      options
    );
  }

  /**
   * Creates a new instance of {@link AuthenticatedChatConnection}.
   *
   * @param username the identifier for the local device
   * @param password the password for the local device
   * @param receiveStories whether or not the local user has Stories enabled, so the server can
   * filter them out ahead of time
   * @param listener the listener for incoming events.
   * @param options additional options to pass through.
   * @param options.languages If provided, a list of languages in Accept-Language syntax to apply
   * to all requests made on this connection. Note that "quality weighting" can be left out; the
   * Signal server will always consider the list to be in priority order.
   * @param options.abortSignal an {@link AbortSignal} that will cancel the connection attempt.
   */
  public connectAuthenticatedChat(
    username: string,
    password: string,
    receiveStories: boolean,
    listener: ChatServiceListener,
    options?: { languages?: string[]; abortSignal?: AbortSignal }
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
  }: {
    sessionId: string;
    e164: string;
  }): Promise<RegistrationService> {
    return RegistrationService.resumeSession(
      {
        connectionManager: this._connectionManager,
        tokioAsyncContext: this.asyncContext,
      },
      { sessionId, e164 }
    );
  }

  public async createRegistrationSession({
    e164,
  }: {
    e164: string;
  }): Promise<RegistrationService> {
    return RegistrationService.createSession(
      {
        connectionManager: this._connectionManager,
        tokioAsyncContext: this.asyncContext,
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

  /**
   * Updates libsignal's remote configuration settings.
   *
   * The provided configuration map must conform to the following requirements:
   * - Each key represents an enabled configuration and directly indicates that the setting is enabled.
   * - Keys must have had the platform-specific prefix (e.g., `"desktop.libsignal."`) removed.
   * - Entries explicitly disabled by the server must not appear in the map.
   * - Values originally set to `null` by the server must be represented as empty strings.
   * - Values should otherwise maintain the same format as they are returned by the server.
   *
   * These constraints ensure configurations passed to libsignal precisely reflect enabled
   * server-provided settings without ambiguity.
   *
   * Only new connections made *after* this call will use the new remote config settings.
   * Existing connections are not affected.
   *
   * @deprecated Calling without buildVariant is deprecated. Please explicitly specify BuildVariant.Production or BuildVariant.Beta.
   * @param remoteConfig A map containing preprocessed libsignal configuration keys and their associated values.
   */
  setRemoteConfig(
    remoteConfig: ReadonlyMap<(typeof REMOTE_CONFIG_KEYS)[number], string>
  ): void;
  /**
   * Updates libsignal's remote configuration settings.
   *
   * The provided configuration map must conform to the following requirements:
   * - Each key represents an enabled configuration and directly indicates that the setting is enabled.
   * - Keys must have had the platform-specific prefix (e.g., `"desktop.libsignal."`) removed.
   * - Entries explicitly disabled by the server must not appear in the map.
   * - Values originally set to `null` by the server must be represented as empty strings.
   * - Values should otherwise maintain the same format as they are returned by the server.
   *
   * These constraints ensure configurations passed to libsignal precisely reflect enabled
   * server-provided settings without ambiguity.
   *
   * Only new connections made *after* this call will use the new remote config settings.
   * Existing connections are not affected.
   *
   * @param remoteConfig A map containing preprocessed libsignal configuration keys and their associated values.
   * @param buildVariant The build variant (BuildVariant.Production or BuildVariant.Beta) that determines which remote config keys to use.
   */
  setRemoteConfig(
    remoteConfig: ReadonlyMap<string, string>,
    buildVariant: BuildVariant
  ): void;
  setRemoteConfig(
    remoteConfig: ReadonlyMap<string, string>,
    buildVariant: BuildVariant = BuildVariant.Production
  ): void {
    Native.ConnectionManager_set_remote_config(
      this._connectionManager,
      new BridgedStringMap(remoteConfig),
      buildVariant
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

  /**
   * Get the SVR-B (Secure Value Recovery for Backups) service for this network instance.
   *
   * SVR-B provides forward secrecy for Signal backups, ensuring that even if the user's
   * Account Entropy Pool or Backup Key is compromised, the attacker cannot
   * compromise all past backups. This is achieved by storing the forward
   * secrecy token in a secure enclave inside the SVR-B server, which provably
   * attests that it only stores a single token at a time for each user.
   *
   * @param auth The authentication credentials to use when connecting to the SVR-B server.
   * @returns An SvrB service instance configured for this network environment
   * @see {@link SvrB}
   */
  svrB(auth: Readonly<ServiceAuth>): SvrB {
    const env = this.options.localTestServer
      ? Environment.Staging
      : this.options.env;
    return new SvrB(this.asyncContext, this._connectionManager, auth, env);
  }
}
