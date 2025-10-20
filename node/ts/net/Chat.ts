//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import { LibSignalError } from '../Errors.js';
import { Environment, TokioAsyncContext } from '../net.js';
import * as KT from './KeyTransparency.js';
import { newNativeHandle } from '../internal.js';
import { FakeChatRemote } from './FakeChat.js';

const DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS = 5000;

export type ChatRequest = Readonly<{
  verb: string;
  path: string;
  headers: ReadonlyArray<[string, string]>;
  body?: Uint8Array;
  timeoutMillis?: number;
}>;

export type RequestOptions = {
  abortSignal?: AbortSignal;
};

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

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
  onConnectionInterrupted: (cause: LibSignalError | null) => void;
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
  onIncomingMessage: (
    envelope: Uint8Array,
    timestamp: number,
    ack: ChatServerMessageAck
  ) => void;

  /**
   * Called when the server indicates that there are no further messages in the message queue.
   *
   * Note that further messages may still be delivered; this merely indicates that all messages that
   * were in the queue *when the connection was established* have been delivered.
   */
  onQueueEmpty: () => void;

  /**
   * Called when the server has alerts for the current device.
   *
   * In practice this happens as part of the connecting process.
   */
  onReceivedAlerts?: (alerts: string[]) => void;
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
  disconnect: () => Promise<void>;

  /**
   * Sends request to the Chat service.
   */
  fetch: (
    chatRequest: ChatRequest,
    options?: RequestOptions
  ) => Promise<Native.ChatResponse>;

  /**
   * Information about the connection to the Chat service.
   */
  connectionInfo: () => ConnectionInfo;
};

export interface ConnectionInfo {
  localPort: number;
  ipVersion: 'IPv4' | 'IPv6';
  toString: () => string;
}

class ConnectionInfoImpl
  implements Native.Wrapper<Native.ChatConnectionInfo>, ConnectionInfo
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
    env?: Environment,
    options?: { languages?: string[]; abortSignal?: AbortSignal }
  ): Promise<UnauthenticatedChatConnection> {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    const connect = Native.UnauthenticatedChatConnection_connect(
      asyncContext,
      connectionManager,
      options?.languages ?? []
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
      nativeChatListener,
      env
    );
  }

  /**
   * Creates a chat connection backed by a fake remote end.
   *
   * @param asyncContext the async runtime to use
   * @param listener the listener to send events to
   * @returns an {@link UnauthenticatedChatConnection} and handle for the remote
   * end of the fake connection.
   */
  public static fakeConnect(
    asyncContext: TokioAsyncContext,
    listener: ChatServiceListener
  ): [UnauthenticatedChatConnection, FakeChatRemote] {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);

    const fakeChat = newNativeHandle(
      Native.TESTING_FakeChatConnection_Create(
        asyncContext,
        new WeakListenerWrapper(nativeChatListener),
        ''
      )
    );

    const chat = newNativeHandle(
      Native.TESTING_FakeChatConnection_TakeUnauthenticatedChat(fakeChat)
    );

    return [
      new UnauthenticatedChatConnection(asyncContext, chat, nativeChatListener),
      new FakeChatRemote(
        asyncContext,
        Native.TESTING_FakeChatConnection_TakeRemote(fakeChat)
      ),
    ];
  }

  private constructor(
    // Not true-private so that they can be accessed by the "Service" interfaces in chat/.
    readonly _asyncContext: TokioAsyncContext,
    readonly _chatService: Native.Wrapper<Native.UnauthenticatedChatConnection>,
    // Unused except to keep the listener alive since the Rust code only holds a
    // weak reference to the same object.
    private readonly chatListener: Native.ChatListener,
    private readonly env?: Environment
  ) {}

  fetch(
    chatRequest: ChatRequest,
    options?: RequestOptions
  ): Promise<Native.ChatResponse> {
    return this._asyncContext.makeCancellable(
      options?.abortSignal,
      Native.UnauthenticatedChatConnection_send(
        this._asyncContext,
        this._chatService,
        buildHttpRequest(chatRequest),
        chatRequest.timeoutMillis ?? DEFAULT_CHAT_REQUEST_TIMEOUT_MILLIS
      )
    );
  }

  disconnect(): Promise<void> {
    return Native.UnauthenticatedChatConnection_disconnect(
      this._asyncContext,
      this._chatService
    );
  }

  connectionInfo(): ConnectionInfo {
    return new ConnectionInfoImpl(
      Native.UnauthenticatedChatConnection_info(this._chatService)
    );
  }

  keyTransparencyClient(): KT.Client {
    if (this.env == null) {
      throw new Error('KeyTransparency is not supported on local test server');
    }
    return new KT.ClientImpl(this._asyncContext, this._chatService, this.env);
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
    options?: { languages?: string[]; abortSignal?: AbortSignal }
  ): Promise<AuthenticatedChatConnection> {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);
    const connect = Native.AuthenticatedChatConnection_connect(
      asyncContext,
      connectionManager,
      username,
      password,
      receiveStories,
      options?.languages ?? []
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
   * @param alerts alerts to send immediately upon connect
   * @returns an {@link AuthenticatedChatConnection} and handle for the remote
   * end of the fake connection.
   */
  public static fakeConnect(
    asyncContext: TokioAsyncContext,
    listener: ChatServiceListener,
    alerts?: ReadonlyArray<string>
  ): [AuthenticatedChatConnection, FakeChatRemote] {
    const nativeChatListener = makeNativeChatListener(asyncContext, listener);

    const fakeChat = newNativeHandle(
      Native.TESTING_FakeChatConnection_Create(
        asyncContext,
        new WeakListenerWrapper(nativeChatListener),
        alerts?.join('\n') ?? ''
      )
    );

    const chat = newNativeHandle(
      Native.TESTING_FakeChatConnection_TakeAuthenticatedChat(fakeChat)
    );

    return [
      new AuthenticatedChatConnection(asyncContext, chat, nativeChatListener),
      new FakeChatRemote(
        asyncContext,
        Native.TESTING_FakeChatConnection_TakeRemote(fakeChat)
      ),
    ];
  }

  private constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly chatService: Native.Wrapper<Native.AuthenticatedChatConnection>,
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
    envelope: Uint8Array,
    timestamp: number,
    ack: Native.ServerMessageAck
  ): void {
    this.listener.deref()?._incoming_message(envelope, timestamp, ack);
  }
  _queue_empty(): void {
    this.listener.deref()?._queue_empty();
  }
  _received_alerts(alerts: string[]): void {
    this.listener.deref()?._received_alerts(alerts);
  }
}

function makeNativeChatListener(
  asyncContext: TokioAsyncContext,
  listener: ConnectionEventsListener | ChatServiceListener
): Native.ChatListener {
  if ('onQueueEmpty' in listener) {
    return {
      _incoming_message(
        envelope: Uint8Array,
        timestamp: number,
        ack: Native.ServerMessageAck
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
      _received_alerts(alerts: string[]): void {
        listener.onReceivedAlerts?.(alerts);
      },
      _connection_interrupted(cause: Error | null): void {
        listener.onConnectionInterrupted(cause as LibSignalError | null);
      },
    };
  }

  return {
    _incoming_message(
      _envelope: Uint8Array,
      _timestamp: number,
      _ack: Native.ServerMessageAck
    ): void {
      throw new Error('Event not supported on unauthenticated connection');
    },
    _queue_empty(): void {
      throw new Error('Event not supported on unauthenticated connection');
    },
    _received_alerts(alerts: string[]): void {
      if (alerts.length != 0) {
        throw new Error(
          `Got ${alerts.length} unexpected alerts on an unauthenticated connection`
        );
      }
    },
    _connection_interrupted(cause: Error | null): void {
      listener.onConnectionInterrupted(cause as LibSignalError);
    },
  };
}

export function buildHttpRequest(
  chatRequest: ChatRequest
): Native.Wrapper<Native.HttpRequest> {
  const { verb, path, body, headers } = chatRequest;
  const httpRequest = {
    _nativeHandle: Native.HttpRequest_new(verb, path, body ?? null),
  };
  headers.forEach((header) => {
    const [name, value] = header;
    Native.HttpRequest_add_header(httpRequest, name, value);
  });
  return httpRequest;
}
