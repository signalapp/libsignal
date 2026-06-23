//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

export type Uuid = Uint8Array<ArrayBuffer>;

/// A Native.Timestamp may be measured in seconds or in milliseconds;
/// what's important is that it's an integer less than Number.MAX_SAFE_INTEGER.
export type Timestamp = number;

// Rust code produces or consumes values that conform to these interface
// definitions. They must be kept in sync to prevent bridging errors.

export type LookupResponse = {
  entries: Map<string, LookupResponseEntry>;
  debugPermitsUsed: number;
};

export type LookupResponseEntry = {
  readonly aci: string | undefined;
  readonly pni: string | undefined;
};

export type ChatResponse = {
  status: number;
  message: string | undefined;
  headers: ReadonlyArray<[string, string]>;
  body: Uint8Array<ArrayBuffer> | undefined;
};

export type ChatServiceDebugInfo = {
  ipType: number;
  durationMillis: number;
  connectionInfo: string;
};

export type ResponseAndDebugInfo = {
  response: ChatResponse;
  debugInfo: ChatServiceDebugInfo;
};

export type SealedSenderMultiRecipientMessageRecipient = {
  deviceIds: number[];
  registrationIds: number[];
  rangeOffset: number;
  rangeLen: number;
};

export type SealedSenderMultiRecipientMessage = {
  recipientMap: {
    [serviceId: string]: SealedSenderMultiRecipientMessageRecipient;
  };
  excludedRecipients: string[];
  offsetOfSharedData: number;
};

export enum IdentityChange {
  // This must be kept in sync with the Rust enum of the same name.
  NewOrUnchanged = 0,
  ReplacedExisting = 1,
}

export type SyncInputStream = Uint8Array<ArrayBuffer>;

export type ChallengeOption = 'pushChallenge' | 'captcha';

export type RegistrationPushTokenType = 'apn' | 'fcm';

export type RegistrationCreateSessionRequest = {
  number: string;
  push_token?: string;
  push_token_type?: RegistrationPushTokenType;
  mcc?: string;
  mnc?: string;
};

export type RegisterResponseBadge = {
  id: string;
  visible: boolean;
  expirationSeconds: number;
};

export type CheckSvr2CredentialsResponse = Map<
  string,
  'match' | 'no-match' | 'invalid'
>;

export type SignedPublicPreKey = {
  keyId: number;
  publicKey: Uint8Array<ArrayBuffer>;
  signature: Uint8Array<ArrayBuffer>;
};

export type Wrapper<T> = Readonly<{
  _nativeHandle: T;
}>;

export type MessageBackupValidationOutcome = {
  errorMessage: string | null;
  unknownFieldMessages: Array<string>;
};

export type JsonFrameExportResult = [
  line: string | null,
  errorMessage: string | null
];

export type PreKeysResponse = {
  identityKey: PublicKey;
  preKeyBundles: PreKeyBundle[];
};

export type UploadForm = {
  cdn: number;
  key: string;
  headers: [string, string][];
  signedUploadUrl: string;
};

export type AccountEntropyPool = string;

export type RandomNumberGenerator = number;

export type CancellablePromise<T> = Promise<T> & {
  _cancellationToken: bigint;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type Serialized<T> = Uint8Array<ArrayBuffer>;

type ConnectChatBridge = Wrapper<ConnectionManager>;
type TestingFutureCancellationGuard = Wrapper<TestingFutureCancellationCounter>;

export type GrpcTestCase<Req, Resp> = {
  name: string;
  method: string;
  request: Req;
  requestGrpc: Uint8Array<ArrayBuffer>;
  responseGrpc: Uint8Array<ArrayBuffer>;
  response: Resp;
};
export type GrpcTestCaseFfi<Req, Resp> = GrpcTestCase<Req, Resp>;

// Keep in sync with rust/bridge/node/src/logging.rs
export const enum LogLevel {
  Error = 1,
  Warn,
  Info,
  Debug,
  Trace,
}

export type ReturnFfiMyRemoteDeriveEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
      _0: number;
      _1: number;
    }
  | {
      __type: 2;
      x: string;
      y: number;
    };

export type ReturnFfiMyRemoteDeriveStruct = {
  x: number;
  y: number;
};

export type ReturnFfiMySimpleTestEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
    };

export type ReturnFfiMyTestEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
      _0: number;
    }
  | {
      __type: 2;
      x: number;
    }
  | {
      __type: 3;
      _0: number;
      _1: number;
    }
  | {
      __type: 4;
      person_name: string;
      person_age: number;
      position: ReturnFfiMyTestPoint;
      fun_struct: ReturnFfiMyTestStruct;
    };

export type ReturnFfiMyTestPoint = {
  _0: number;
  _1: number;
};

export type ReturnFfiMyTestStruct = {
  my_numeric_field: number;
  my_string_field: string;
};

export type ReturnFfiSetDeviceNameArgs = {
  id: number;
  encrypted_name: Uint8Array<ArrayBuffer>;
};

export type ReturnFfiSetDeviceNameOut =
  | {
      __type: 0;
    }
  | {
      __type: 1;
    };

export type ArgFfiMyRemoteDeriveEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
      _0: number;
      _1: number;
    }
  | {
      __type: 2;
      x: string;
      y: number;
    };

export type ArgFfiMyRemoteDeriveStruct = {
  x: number;
  y: number;
};

export type ArgFfiMySimpleTestEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
    };

export type ArgFfiMyTestEnum =
  | {
      __type: 0;
    }
  | {
      __type: 1;
      _0: number;
    }
  | {
      __type: 2;
      x: number;
    }
  | {
      __type: 3;
      _0: number;
      _1: number;
    }
  | {
      __type: 4;
      person_name: string;
      person_age: number;
      position: ArgFfiMyTestPoint;
      fun_struct: ArgFfiMyTestStruct;
    };

export type ArgFfiMyTestPoint = {
  _0: number;
  _1: number;
};

export type ArgFfiMyTestStruct = {
  my_numeric_field: number;
  my_string_field: string;
};

/* eslint-disable comma-dangle */
export const NetRemoteConfigKeys = [
  'chatRequestConnectionCheckTimeoutMillis',
  'useH2ForUnauthChat',
  'useH2ForAuthChat',
  'grpc.AccountsAnonymousLookupUsernameHash',
  'grpc.AccountsAnonymousLookupUsernameLink.2',
  'grpc.AccountsAnonymousCheckAccountExistence.2',
  'grpc.MessagesAnonymousSendMultiRecipientMessage.2',
  'grpc.MessagesAnonymousSendSingleRecipientMessage',
  'grpc.AttachmentsGetUploadForm',
  'grpc.MessagesSendMessage',
  'grpc.BackupsAnonymousGetUploadForm',
] as const;

import load from 'node-gyp-build';

type NativeFunctions = {
  registerErrors: (errorsModule: Record<string, unknown>) => void;
  initLogger: (
    maxLevel: LogLevel,
    callback: (
      level: LogLevel,
      target: string,
      file: string | null,
      line: number | null,
      message: string
    ) => void
  ) => void;
  AccountEntropyPool_DeriveBackupKey: (
    account_entropy: AccountEntropyPool
  ) => Uint8Array<ArrayBuffer>;
  AccountEntropyPool_DeriveSvrKey: (
    account_entropy: AccountEntropyPool
  ) => Uint8Array<ArrayBuffer>;
  AccountEntropyPool_Generate: () => string;
  AccountEntropyPool_IsValid: (account_entropy: string) => boolean;
  Aes256GcmSiv_Decrypt: (
    aes_gcm_siv: Wrapper<Aes256GcmSiv>,
    ctext: Uint8Array<ArrayBuffer>,
    nonce: Uint8Array<ArrayBuffer>,
    associated_data: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  Aes256GcmSiv_Encrypt: (
    aes_gcm_siv_obj: Wrapper<Aes256GcmSiv>,
    ptext: Uint8Array<ArrayBuffer>,
    nonce: Uint8Array<ArrayBuffer>,
    associated_data: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  Aes256GcmSiv_New: (key: Uint8Array<ArrayBuffer>) => Aes256GcmSiv;
  AuthCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AuthCredentialPresentation_GetPniCiphertext: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  AuthCredentialPresentation_GetRedemptionTime: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  AuthCredentialPresentation_GetUuidCiphertext: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  AuthCredentialWithPniResponse_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AuthCredentialWithPni_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AuthenticatedChatConnection_connect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string,
    receive_stories: boolean,
    languages: Array<string>
  ) => CancellablePromise<AuthenticatedChatConnection>;
  AuthenticatedChatConnection_disconnect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>
  ) => CancellablePromise<void>;
  AuthenticatedChatConnection_get_upload_form: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    upload_length: bigint
  ) => CancellablePromise<UploadForm>;
  AuthenticatedChatConnection_info: (
    chat: Wrapper<AuthenticatedChatConnection>
  ) => ChatConnectionInfo;
  AuthenticatedChatConnection_init_listener: (
    chat: Wrapper<AuthenticatedChatConnection>,
    listener: ChatListener
  ) => void;
  AuthenticatedChatConnection_preconnect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>
  ) => CancellablePromise<void>;
  AuthenticatedChatConnection_send: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    http_request: Wrapper<HttpRequest>,
    timeout_millis: number
  ) => CancellablePromise<ChatResponse>;
  AuthenticatedChatConnection_send_message: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    destination: Uint8Array<ArrayBuffer>,
    timestamp: Timestamp,
    device_ids: Uint32Array<ArrayBuffer>,
    registration_ids: Uint32Array<ArrayBuffer>,
    contents: Array<Wrapper<CiphertextMessage>>,
    online_only: boolean,
    is_urgent: boolean
  ) => CancellablePromise<void>;
  AuthenticatedChatConnection_send_raw_grpc: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    service: string,
    method: string,
    payload: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  AuthenticatedChatConnection_send_sync_message: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    timestamp: Timestamp,
    device_ids: Uint32Array<ArrayBuffer>,
    registration_ids: Uint32Array<ArrayBuffer>,
    contents: Array<Wrapper<CiphertextMessage>>,
    is_urgent: boolean
  ) => CancellablePromise<void>;
  AuthenticatedChatConnection_set_device_name: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<AuthenticatedChatConnection>,
    device_id: number,
    encrypted_name: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<void>;
  AvatarUploadCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredentialPresentation_GetCm: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredentialPresentation_GetRedemptionTime: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  AvatarUploadCredentialPresentation_Verify: (
    presentation_bytes: Uint8Array<ArrayBuffer>,
    current_time: Timestamp,
    server_params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredentialRequestContext_CheckValidContents: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredentialRequestContext_GetRequest: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredentialRequestContext_New: (
    aci: Uint8Array<ArrayBuffer>,
    zk_credential_key_pair_bytes: Uint8Array<ArrayBuffer>,
    rotation_id: bigint,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredentialRequestContext_ReceiveResponse: (
    context_bytes: Uint8Array<ArrayBuffer>,
    response_bytes: Uint8Array<ArrayBuffer>,
    current_time: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredentialRequest_CheckValidContents: (
    request_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredentialRequest_IssueDeterministic: (
    request_bytes: Uint8Array<ArrayBuffer>,
    aci: Uint8Array<ArrayBuffer>,
    zk_credential_key_pub_bytes: Uint8Array<ArrayBuffer>,
    rotation_id: bigint,
    redemption_time: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredentialResponse_CheckValidContents: (
    response_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredential_CheckValidContents: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  AvatarUploadCredential_GetCm: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  AvatarUploadCredential_GetRedemptionTime: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  AvatarUploadCredential_PresentDeterministic: (
    credential_bytes: Uint8Array<ArrayBuffer>,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredentialPresentation_GetBackupId: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialPresentation_GetBackupLevel: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => number;
  BackupAuthCredentialPresentation_GetType: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => number;
  BackupAuthCredentialPresentation_Verify: (
    presentation_bytes: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    server_params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredentialRequestContext_CheckValidContents: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredentialRequestContext_GetRequest: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialRequestContext_New: (
    backup_key: Uint8Array<ArrayBuffer>,
    uuid: Uuid
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialRequestContext_ReceiveResponse: (
    context_bytes: Uint8Array<ArrayBuffer>,
    response_bytes: Uint8Array<ArrayBuffer>,
    expected_redemption_time: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialRequest_CheckValidContents: (
    request_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredentialRequest_IssueDeterministic: (
    request_bytes: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp,
    backup_level: number,
    credential_type: number,
    params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredentialResponse_CheckValidContents: (
    response_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredential_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  BackupAuthCredential_GetBackupId: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupAuthCredential_GetBackupLevel: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => number;
  BackupAuthCredential_GetType: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => number;
  BackupAuthCredential_PresentDeterministic: (
    credential_bytes: Uint8Array<ArrayBuffer>,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupJsonExporter_ExportFrames: (
    exporter: Wrapper<BackupJsonExporter>,
    frames: Uint8Array<ArrayBuffer>
  ) => Array<[string | null, string | null]>;
  BackupJsonExporter_Finish: (exporter: Wrapper<BackupJsonExporter>) => void;
  BackupJsonExporter_GetInitialChunk: (
    exporter: Wrapper<BackupJsonExporter>
  ) => string;
  BackupJsonExporter_New: (
    backup_info: Uint8Array<ArrayBuffer>,
    should_validate: boolean
  ) => BackupJsonExporter;
  BackupKey_DeriveBackupId: (
    backup_key: Uint8Array<ArrayBuffer>,
    aci: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupKey_DeriveEcKey: (
    backup_key: Uint8Array<ArrayBuffer>,
    aci: Uint8Array<ArrayBuffer>
  ) => PrivateKey;
  BackupKey_DeriveLocalBackupMetadataKey: (
    backup_key: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupKey_DeriveMediaEncryptionKey: (
    backup_key: Uint8Array<ArrayBuffer>,
    media_id: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupKey_DeriveMediaId: (
    backup_key: Uint8Array<ArrayBuffer>,
    media_name: string
  ) => Uint8Array<ArrayBuffer>;
  BackupKey_DeriveThumbnailTransitEncryptionKey: (
    backup_key: Uint8Array<ArrayBuffer>,
    media_id: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  BackupRestoreResponse_GetForwardSecrecyToken: (
    response: Wrapper<BackupRestoreResponse>
  ) => Uint8Array<ArrayBuffer>;
  BackupRestoreResponse_GetNextBackupSecretData: (
    response: Wrapper<BackupRestoreResponse>
  ) => Uint8Array<ArrayBuffer>;
  BackupStoreResponse_GetForwardSecrecyToken: (
    response: Wrapper<BackupStoreResponse>
  ) => Uint8Array<ArrayBuffer>;
  BackupStoreResponse_GetNextBackupSecretData: (
    response: Wrapper<BackupStoreResponse>
  ) => Uint8Array<ArrayBuffer>;
  BackupStoreResponse_GetOpaqueMetadata: (
    response: Wrapper<BackupStoreResponse>
  ) => Uint8Array<ArrayBuffer>;
  BridgedStringMap_insert: (
    map: Wrapper<BridgedStringMap>,
    key: string,
    value: string
  ) => void;
  BridgedStringMap_new: (initial_capacity: number) => BridgedStringMap;
  CallLinkAuthCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkAuthCredentialPresentation_GetUserId: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  CallLinkAuthCredentialPresentation_Verify: (
    presentation_bytes: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    call_link_params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkAuthCredentialResponse_CheckValidContents: (
    response_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkAuthCredentialResponse_IssueDeterministic: (
    user_id: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CallLinkAuthCredentialResponse_Receive: (
    response_bytes: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CallLinkAuthCredential_CheckValidContents: (
    credential_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkAuthCredential_PresentDeterministic: (
    credential_bytes: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    call_link_params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CallLinkPublicParams_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkSecretParams_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CallLinkSecretParams_DecryptUserId: (
    params_bytes: Uint8Array<ArrayBuffer>,
    user_id: Serialized<UuidCiphertext>
  ) => Uint8Array<ArrayBuffer>;
  CallLinkSecretParams_DeriveFromRootKey: (
    root_key: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CallLinkSecretParams_EncryptUserId: (
    params_bytes: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  CallLinkSecretParams_GetPublicParams: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  Cds2ClientState_New: (
    mrenclave: Uint8Array<ArrayBuffer>,
    attestation_msg: Uint8Array<ArrayBuffer>,
    current_timestamp: Timestamp
  ) => SgxClientState;
  CdsiLookup_complete: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    lookup: Wrapper<CdsiLookup>
  ) => CancellablePromise<LookupResponse>;
  CdsiLookup_new: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string,
    request: Wrapper<LookupRequest>
  ) => CancellablePromise<CdsiLookup>;
  CdsiLookup_token: (lookup: Wrapper<CdsiLookup>) => Uint8Array<ArrayBuffer>;
  ChatConnectionInfo_description: (
    connection_info: Wrapper<ChatConnectionInfo>
  ) => string;
  ChatConnectionInfo_ip_version: (
    connection_info: Wrapper<ChatConnectionInfo>
  ) => number;
  ChatConnectionInfo_local_port: (
    connection_info: Wrapper<ChatConnectionInfo>
  ) => number;
  CiphertextMessage_FromPlaintextContent: (
    m: Wrapper<PlaintextContent>
  ) => CiphertextMessage;
  CiphertextMessage_Serialize: (
    obj: Wrapper<CiphertextMessage>
  ) => Uint8Array<ArrayBuffer>;
  CiphertextMessage_Type: (msg: Wrapper<CiphertextMessage>) => number;
  ComparableBackup_GetComparableString: (
    backup: Wrapper<ComparableBackup>
  ) => string;
  ComparableBackup_GetUnknownFields: (
    backup: Wrapper<ComparableBackup>
  ) => Array<string>;
  ComparableBackup_ReadUnencrypted: (
    stream: InputStream,
    len: bigint,
    purpose: number
  ) => Promise<ComparableBackup>;
  ConnectionManager_clear_proxy: (
    connection_manager: Wrapper<ConnectionManager>
  ) => void;
  ConnectionManager_new: (
    environment: number,
    user_agent: string,
    remote_config: Wrapper<BridgedStringMap>,
    build_variant: number
  ) => ConnectionManager;
  ConnectionManager_on_network_change: (
    connection_manager: Wrapper<ConnectionManager>
  ) => void;
  ConnectionManager_set_censorship_circumvention_enabled: (
    connection_manager: Wrapper<ConnectionManager>,
    enabled: boolean
  ) => void;
  ConnectionManager_set_invalid_proxy: (
    connection_manager: Wrapper<ConnectionManager>
  ) => void;
  ConnectionManager_set_ipv6_enabled: (
    connection_manager: Wrapper<ConnectionManager>,
    ipv6_enabled: boolean
  ) => void;
  ConnectionManager_set_proxy: (
    connection_manager: Wrapper<ConnectionManager>,
    proxy: Wrapper<ConnectionProxyConfig>
  ) => void;
  ConnectionManager_set_remote_config: (
    connection_manager: Wrapper<ConnectionManager>,
    remote_config: Wrapper<BridgedStringMap>,
    build_variant: number
  ) => void;
  ConnectionProxyConfig_new: (
    scheme: string,
    host: string,
    port: number,
    username: string | null,
    password: string | null
  ) => ConnectionProxyConfig;
  CreateCallLinkCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredentialPresentation_Verify: (
    presentation_bytes: Uint8Array<ArrayBuffer>,
    room_id: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    call_link_params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredentialRequestContext_CheckValidContents: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredentialRequestContext_GetRequest: (
    context_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CreateCallLinkCredentialRequestContext_NewDeterministic: (
    room_id: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CreateCallLinkCredentialRequestContext_ReceiveResponse: (
    context_bytes: Uint8Array<ArrayBuffer>,
    response_bytes: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CreateCallLinkCredentialRequest_CheckValidContents: (
    request_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredentialRequest_IssueDeterministic: (
    request_bytes: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    timestamp: Timestamp,
    params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  CreateCallLinkCredentialResponse_CheckValidContents: (
    response_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredential_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  CreateCallLinkCredential_PresentDeterministic: (
    credential_bytes: Uint8Array<ArrayBuffer>,
    room_id: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    server_params_bytes: Uint8Array<ArrayBuffer>,
    call_link_params_bytes: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  DecryptionErrorMessage_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => DecryptionErrorMessage;
  DecryptionErrorMessage_ExtractFromSerializedContent: (
    bytes: Uint8Array<ArrayBuffer>
  ) => DecryptionErrorMessage;
  DecryptionErrorMessage_ForOriginalMessage: (
    original_bytes: Uint8Array<ArrayBuffer>,
    original_type: number,
    original_timestamp: Timestamp,
    original_sender_device_id: number
  ) => DecryptionErrorMessage;
  DecryptionErrorMessage_GetDeviceId: (
    obj: Wrapper<DecryptionErrorMessage>
  ) => number;
  DecryptionErrorMessage_GetRatchetKey: (
    m: Wrapper<DecryptionErrorMessage>
  ) => PublicKey | null;
  DecryptionErrorMessage_GetTimestamp: (
    obj: Wrapper<DecryptionErrorMessage>
  ) => Timestamp;
  DecryptionErrorMessage_Serialize: (
    obj: Wrapper<DecryptionErrorMessage>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermitDerivedKeyPair_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  DonationPermitDerivedKeyPair_ForExpiration: (
    timestamp: Timestamp,
    root: Wrapper<ServerSecretParams>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermitRequestContext_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  DonationPermitRequestContext_NewDeterministic: (
    count: number,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermitRequestContext_Receive: (
    context: Uint8Array<ArrayBuffer>,
    response: Uint8Array<ArrayBuffer>,
    public_params: Wrapper<ServerPublicParams>,
    now: Timestamp
  ) => Array<Uint8Array<ArrayBuffer>>;
  DonationPermitRequestContext_Request: (
    ctx: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermitRequest_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  DonationPermitRequest_Len: (
    donation_permit_request: Uint8Array<ArrayBuffer>
  ) => number;
  DonationPermitResponse_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  DonationPermitResponse_DefaultExpiration: (
    current_time: Timestamp
  ) => Timestamp;
  DonationPermitResponse_GetExpiration: (
    response: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  DonationPermitResponse_IssueDeterministic: (
    request: Uint8Array<ArrayBuffer>,
    key_pair: Uint8Array<ArrayBuffer>,
    seed: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermit_CheckValidContents: (buffer: Uint8Array<ArrayBuffer>) => void;
  DonationPermit_Expiration: (
    donation_permit: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  DonationPermit_SpendId: (
    donation_permit: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  DonationPermit_Verify: (
    permit: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    key_pair: Uint8Array<ArrayBuffer>
  ) => void;
  ExpiringProfileKeyCredentialResponse_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ExpiringProfileKeyCredential_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ExpiringProfileKeyCredential_GetExpirationTime: (
    credential: Serialized<ExpiringProfileKeyCredential>
  ) => Timestamp;
  Fingerprint_DisplayString: (obj: Wrapper<Fingerprint>) => string;
  Fingerprint_New: (
    iterations: number,
    version: number,
    local_identifier: Uint8Array<ArrayBuffer>,
    local_key: Wrapper<PublicKey>,
    remote_identifier: Uint8Array<ArrayBuffer>,
    remote_key: Wrapper<PublicKey>
  ) => Fingerprint;
  Fingerprint_ScannableEncoding: (
    obj: Wrapper<Fingerprint>
  ) => Uint8Array<ArrayBuffer>;
  GenericServerPublicParams_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GenericServerSecretParams_CheckValidContents: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GenericServerSecretParams_GenerateDeterministic: (
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GenericServerSecretParams_GetPublicParams: (
    params_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GroupCipher_DecryptMessage: (
    sender: Wrapper<ProtocolAddress>,
    message: Uint8Array<ArrayBuffer>,
    store: SenderKeyStore
  ) => Promise<Uint8Array<ArrayBuffer>>;
  GroupCipher_EncryptMessage: (
    sender: Wrapper<ProtocolAddress>,
    distribution_id: Uuid,
    message: Uint8Array<ArrayBuffer>,
    store: SenderKeyStore
  ) => Promise<CiphertextMessage>;
  GroupMasterKey_CheckValidContents: (buffer: Uint8Array<ArrayBuffer>) => void;
  GroupPublicParams_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  GroupPublicParams_GetGroupIdentifier: (
    group_public_params: Serialized<GroupPublicParams>
  ) => Uint8Array<ArrayBuffer>;
  GroupSecretParams_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSecretParams_DecryptBlobWithPadding: (
    params: Serialized<GroupSecretParams>,
    ciphertext: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GroupSecretParams_DecryptProfileKey: (
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKeyCiphertext>,
    user_id: Uint8Array<ArrayBuffer>
  ) => Serialized<ProfileKey>;
  GroupSecretParams_DecryptServiceId: (
    params: Serialized<GroupSecretParams>,
    ciphertext: Serialized<UuidCiphertext>
  ) => Uint8Array<ArrayBuffer>;
  GroupSecretParams_DeriveFromMasterKey: (
    master_key: Serialized<GroupMasterKey>
  ) => Serialized<GroupSecretParams>;
  GroupSecretParams_EncryptBlobWithPaddingDeterministic: (
    params: Serialized<GroupSecretParams>,
    randomness: Uint8Array<ArrayBuffer>,
    plaintext: Uint8Array<ArrayBuffer>,
    padding_len: number
  ) => Uint8Array<ArrayBuffer>;
  GroupSecretParams_EncryptProfileKey: (
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKey>,
    user_id: Uint8Array<ArrayBuffer>
  ) => Serialized<ProfileKeyCiphertext>;
  GroupSecretParams_EncryptServiceId: (
    params: Serialized<GroupSecretParams>,
    service_id: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  GroupSecretParams_GenerateDeterministic: (
    randomness: Uint8Array<ArrayBuffer>
  ) => Serialized<GroupSecretParams>;
  GroupSecretParams_GetMasterKey: (
    params: Serialized<GroupSecretParams>
  ) => Serialized<GroupMasterKey>;
  GroupSecretParams_GetPublicParams: (
    params: Serialized<GroupSecretParams>
  ) => Serialized<GroupPublicParams>;
  GroupSendDerivedKeyPair_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSendDerivedKeyPair_ForExpiration: (
    expiration: Timestamp,
    server_params: Wrapper<ServerSecretParams>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsement_CallLinkParams_ToToken: (
    endorsement: Uint8Array<ArrayBuffer>,
    call_link_secret_params_serialized: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsement_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSendEndorsement_Combine: (
    endorsements: Array<Uint8Array<ArrayBuffer>>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsement_Remove: (
    endorsement: Uint8Array<ArrayBuffer>,
    to_remove: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsement_ToToken: (
    endorsement: Uint8Array<ArrayBuffer>,
    group_params: Serialized<GroupSecretParams>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsementsResponse_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSendEndorsementsResponse_GetExpiration: (
    response_bytes: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  GroupSendEndorsementsResponse_IssueDeterministic: (
    concatenated_group_member_ciphertexts: Uint8Array<ArrayBuffer>,
    key_pair: Uint8Array<ArrayBuffer>,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts: (
    response_bytes: Uint8Array<ArrayBuffer>,
    concatenated_group_member_ciphertexts: Uint8Array<ArrayBuffer>,
    local_user_ciphertext: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    server_params: Wrapper<ServerPublicParams>
  ) => Array<Uint8Array<ArrayBuffer>>;
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds: (
    response_bytes: Uint8Array<ArrayBuffer>,
    group_members: Uint8Array<ArrayBuffer>,
    local_user: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    group_params: Serialized<GroupSecretParams>,
    server_params: Wrapper<ServerPublicParams>
  ) => Array<Uint8Array<ArrayBuffer>>;
  GroupSendFullToken_CheckValidContents: (
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSendFullToken_GetExpiration: (
    token: Uint8Array<ArrayBuffer>
  ) => Timestamp;
  GroupSendFullToken_Verify: (
    token: Uint8Array<ArrayBuffer>,
    user_ids: Uint8Array<ArrayBuffer>,
    now: Timestamp,
    key_pair: Uint8Array<ArrayBuffer>
  ) => void;
  GroupSendToken_CheckValidContents: (bytes: Uint8Array<ArrayBuffer>) => void;
  GroupSendToken_ToFullToken: (
    token: Uint8Array<ArrayBuffer>,
    expiration: Timestamp
  ) => Uint8Array<ArrayBuffer>;
  HKDF_DeriveSecrets: (
    output_length: number,
    ikm: Uint8Array<ArrayBuffer>,
    label: Uint8Array<ArrayBuffer> | null,
    salt: Uint8Array<ArrayBuffer> | null
  ) => Uint8Array<ArrayBuffer>;
  HsmEnclaveClient_CompleteHandshake: (
    cli: Wrapper<HsmEnclaveClient>,
    handshake_received: Uint8Array<ArrayBuffer>
  ) => void;
  HsmEnclaveClient_EstablishedRecv: (
    cli: Wrapper<HsmEnclaveClient>,
    received_ciphertext: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  HsmEnclaveClient_EstablishedSend: (
    cli: Wrapper<HsmEnclaveClient>,
    plaintext_to_send: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  HsmEnclaveClient_InitialRequest: (
    obj: Wrapper<HsmEnclaveClient>
  ) => Uint8Array<ArrayBuffer>;
  HsmEnclaveClient_New: (
    trusted_public_key: Uint8Array<ArrayBuffer>,
    trusted_code_hashes: Uint8Array<ArrayBuffer>
  ) => HsmEnclaveClient;
  HttpRequest_add_header: (
    request: Wrapper<HttpRequest>,
    name: string,
    value: string
  ) => void;
  HttpRequest_new: (
    method: string,
    path: string,
    body_as_slice: Uint8Array<ArrayBuffer> | null
  ) => HttpRequest;
  IdentityKeyPair_Deserialize: (
    input: Uint8Array<ArrayBuffer>
  ) => [PublicKey, PrivateKey];
  IdentityKeyPair_Serialize: (
    public_key: Wrapper<PublicKey>,
    private_key: Wrapper<PrivateKey>
  ) => Uint8Array<ArrayBuffer>;
  IdentityKeyPair_SignAlternateIdentity: (
    public_key: Wrapper<PublicKey>,
    private_key: Wrapper<PrivateKey>,
    other_identity: Wrapper<PublicKey>
  ) => Uint8Array<ArrayBuffer>;
  IdentityKey_VerifyAlternateIdentity: (
    public_key: Wrapper<PublicKey>,
    other_identity: Wrapper<PublicKey>,
    signature: Uint8Array<ArrayBuffer>
  ) => boolean;
  IncrementalMac_CalculateChunkSize: (data_size: number) => number;
  IncrementalMac_Finalize: (
    mac: Wrapper<IncrementalMac>
  ) => Uint8Array<ArrayBuffer>;
  IncrementalMac_Initialize: (
    key: Uint8Array<ArrayBuffer>,
    chunk_size: number
  ) => IncrementalMac;
  IncrementalMac_Update: (
    mac: Wrapper<IncrementalMac>,
    bytes: Uint8Array<ArrayBuffer>,
    offset: number,
    length: number
  ) => Uint8Array<ArrayBuffer>;
  KeyTransparency_AciSearchKey: (
    aci: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  KeyTransparency_Check: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    environment: number,
    chat_connection: Wrapper<UnauthenticatedChatConnection>,
    aci: Uint8Array<ArrayBuffer>,
    aci_identity_key: Wrapper<PublicKey>,
    e164: string | null,
    unidentified_access_key: Uint8Array<ArrayBuffer> | null,
    username_hash: Uint8Array<ArrayBuffer> | null,
    account_data: Uint8Array<ArrayBuffer> | null,
    last_distinguished_tree_head: Uint8Array<ArrayBuffer> | null,
    is_self_check: boolean,
    is_e164_discoverable: boolean
  ) => CancellablePromise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]>;
  KeyTransparency_E164SearchKey: (e164: string) => Uint8Array<ArrayBuffer>;
  KeyTransparency_ResetDataField: (
    account_data: Uint8Array<ArrayBuffer>,
    field: number
  ) => Uint8Array<ArrayBuffer>;
  KeyTransparency_UsernameHashSearchKey: (
    hash: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  KyberKeyPair_Generate: () => KyberKeyPair;
  KyberKeyPair_GetPublicKey: (
    key_pair: Wrapper<KyberKeyPair>
  ) => KyberPublicKey;
  KyberKeyPair_GetSecretKey: (
    key_pair: Wrapper<KyberKeyPair>
  ) => KyberSecretKey;
  KyberPreKeyRecord_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => KyberPreKeyRecord;
  KyberPreKeyRecord_GetId: (obj: Wrapper<KyberPreKeyRecord>) => number;
  KyberPreKeyRecord_GetKeyPair: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => KyberKeyPair;
  KyberPreKeyRecord_GetPublicKey: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => KyberPublicKey;
  KyberPreKeyRecord_GetSecretKey: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => KyberSecretKey;
  KyberPreKeyRecord_GetSignature: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  KyberPreKeyRecord_GetTimestamp: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => Timestamp;
  KyberPreKeyRecord_New: (
    id: number,
    timestamp: Timestamp,
    key_pair: Wrapper<KyberKeyPair>,
    signature: Uint8Array<ArrayBuffer>
  ) => KyberPreKeyRecord;
  KyberPreKeyRecord_Serialize: (
    obj: Wrapper<KyberPreKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  KyberPublicKey_Deserialize: (data: Uint8Array<ArrayBuffer>) => KyberPublicKey;
  KyberPublicKey_Equals: (
    lhs: Wrapper<KyberPublicKey>,
    rhs: Wrapper<KyberPublicKey>
  ) => boolean;
  KyberPublicKey_Serialize: (
    obj: Wrapper<KyberPublicKey>
  ) => Uint8Array<ArrayBuffer>;
  KyberSecretKey_Deserialize: (data: Uint8Array<ArrayBuffer>) => KyberSecretKey;
  KyberSecretKey_Serialize: (
    obj: Wrapper<KyberSecretKey>
  ) => Uint8Array<ArrayBuffer>;
  LookupRequest_addAciAndAccessKey: (
    request: Wrapper<LookupRequest>,
    aci: Uint8Array<ArrayBuffer>,
    access_key: Uint8Array<ArrayBuffer>
  ) => void;
  LookupRequest_addE164: (
    request: Wrapper<LookupRequest>,
    e164: string
  ) => void;
  LookupRequest_addPreviousE164: (
    request: Wrapper<LookupRequest>,
    e164: string
  ) => void;
  LookupRequest_new: () => LookupRequest;
  LookupRequest_setToken: (
    request: Wrapper<LookupRequest>,
    token: Uint8Array<ArrayBuffer>
  ) => void;
  MessageBackupKey_FromAccountEntropyPool: (
    account_entropy: AccountEntropyPool,
    aci: Uint8Array<ArrayBuffer>,
    forward_secrecy_token: Uint8Array<ArrayBuffer> | null
  ) => MessageBackupKey;
  MessageBackupKey_FromBackupKeyAndBackupId: (
    backup_key: Uint8Array<ArrayBuffer>,
    backup_id: Uint8Array<ArrayBuffer>,
    forward_secrecy_token: Uint8Array<ArrayBuffer> | null
  ) => MessageBackupKey;
  MessageBackupKey_GetAesKey: (
    key: Wrapper<MessageBackupKey>
  ) => Uint8Array<ArrayBuffer>;
  MessageBackupKey_GetHmacKey: (
    key: Wrapper<MessageBackupKey>
  ) => Uint8Array<ArrayBuffer>;
  MessageBackupValidator_Validate: (
    key: Wrapper<MessageBackupKey>,
    first_stream: InputStream,
    second_stream: InputStream,
    len: bigint,
    purpose: number
  ) => Promise<MessageBackupValidationOutcome>;
  MinidumpToJSONString: (buffer: Uint8Array<ArrayBuffer>) => string;
  Mp4Sanitizer_Sanitize: (
    input: InputStream,
    len: bigint
  ) => Promise<SanitizedMetadata>;
  OnlineBackupValidator_AddFrame: (
    backup: Wrapper<OnlineBackupValidator>,
    frame: Uint8Array<ArrayBuffer>
  ) => void;
  OnlineBackupValidator_Finalize: (
    backup: Wrapper<OnlineBackupValidator>
  ) => void;
  OnlineBackupValidator_New: (
    backup_info_frame: Uint8Array<ArrayBuffer>,
    purpose: number
  ) => OnlineBackupValidator;
  PinHash_AccessKey: (ph: Wrapper<PinHash>) => Uint8Array<ArrayBuffer>;
  PinHash_EncryptionKey: (ph: Wrapper<PinHash>) => Uint8Array<ArrayBuffer>;
  PinHash_FromSalt: (
    pin: Uint8Array<ArrayBuffer>,
    salt: Uint8Array<ArrayBuffer>
  ) => PinHash;
  PinHash_FromUsernameMrenclave: (
    pin: Uint8Array<ArrayBuffer>,
    username: string,
    mrenclave: Uint8Array<ArrayBuffer>
  ) => PinHash;
  Pin_LocalHash: (pin: Uint8Array<ArrayBuffer>) => string;
  Pin_VerifyLocalHash: (
    encoded_hash: string,
    pin: Uint8Array<ArrayBuffer>
  ) => boolean;
  PlaintextContent_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => PlaintextContent;
  PlaintextContent_FromDecryptionErrorMessage: (
    m: Wrapper<DecryptionErrorMessage>
  ) => PlaintextContent;
  PlaintextContent_GetBody: (
    obj: Wrapper<PlaintextContent>
  ) => Uint8Array<ArrayBuffer>;
  PlaintextContent_Serialize: (
    obj: Wrapper<PlaintextContent>
  ) => Uint8Array<ArrayBuffer>;
  PreKeyBundle_GetDeviceId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetIdentityKey: (p: Wrapper<PreKeyBundle>) => PublicKey;
  PreKeyBundle_GetKyberPreKeyId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetKyberPreKeyPublic: (
    bundle: Wrapper<PreKeyBundle>
  ) => KyberPublicKey;
  PreKeyBundle_GetKyberPreKeySignature: (
    obj: Wrapper<PreKeyBundle>
  ) => Uint8Array<ArrayBuffer>;
  PreKeyBundle_GetPreKeyId: (obj: Wrapper<PreKeyBundle>) => number | null;
  PreKeyBundle_GetPreKeyPublic: (
    obj: Wrapper<PreKeyBundle>
  ) => PublicKey | null;
  PreKeyBundle_GetRegistrationId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetSignedPreKeyId: (obj: Wrapper<PreKeyBundle>) => number;
  PreKeyBundle_GetSignedPreKeyPublic: (obj: Wrapper<PreKeyBundle>) => PublicKey;
  PreKeyBundle_GetSignedPreKeySignature: (
    obj: Wrapper<PreKeyBundle>
  ) => Uint8Array<ArrayBuffer>;
  PreKeyBundle_New: (
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: Wrapper<PublicKey> | null,
    signed_prekey_id: number,
    signed_prekey: Wrapper<PublicKey>,
    signed_prekey_signature: Uint8Array<ArrayBuffer>,
    identity_key: Wrapper<PublicKey>,
    kyber_prekey_id: number,
    kyber_prekey: Wrapper<KyberPublicKey>,
    kyber_prekey_signature: Uint8Array<ArrayBuffer>
  ) => PreKeyBundle;
  PreKeyRecord_Deserialize: (data: Uint8Array<ArrayBuffer>) => PreKeyRecord;
  PreKeyRecord_GetId: (obj: Wrapper<PreKeyRecord>) => number;
  PreKeyRecord_GetPrivateKey: (obj: Wrapper<PreKeyRecord>) => PrivateKey;
  PreKeyRecord_GetPublicKey: (obj: Wrapper<PreKeyRecord>) => PublicKey;
  PreKeyRecord_New: (
    id: number,
    pub_key: Wrapper<PublicKey>,
    priv_key: Wrapper<PrivateKey>
  ) => PreKeyRecord;
  PreKeyRecord_Serialize: (
    obj: Wrapper<PreKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  PreKeySignalMessage_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => PreKeySignalMessage;
  PreKeySignalMessage_GetPreKeyId: (
    obj: Wrapper<PreKeySignalMessage>
  ) => number | null;
  PreKeySignalMessage_GetRegistrationId: (
    obj: Wrapper<PreKeySignalMessage>
  ) => number;
  PreKeySignalMessage_GetSignedPreKeyId: (
    obj: Wrapper<PreKeySignalMessage>
  ) => number;
  PreKeySignalMessage_GetVersion: (obj: Wrapper<PreKeySignalMessage>) => number;
  PreKeySignalMessage_New: (
    message_version: number,
    registration_id: number,
    pre_key_id: number | null,
    signed_pre_key_id: number,
    base_key: Wrapper<PublicKey>,
    identity_key: Wrapper<PublicKey>,
    signal_message: Wrapper<SignalMessage>
  ) => PreKeySignalMessage;
  PreKeySignalMessage_Serialize: (
    obj: Wrapper<PreKeySignalMessage>
  ) => Uint8Array<ArrayBuffer>;
  PrivateKey_Agree: (
    private_key: Wrapper<PrivateKey>,
    public_key: Wrapper<PublicKey>
  ) => Uint8Array<ArrayBuffer>;
  PrivateKey_Deserialize: (data: Uint8Array<ArrayBuffer>) => PrivateKey;
  PrivateKey_Generate: () => PrivateKey;
  PrivateKey_GetPublicKey: (k: Wrapper<PrivateKey>) => PublicKey;
  PrivateKey_HpkeOpen: (
    sk: Wrapper<PrivateKey>,
    ciphertext: Uint8Array<ArrayBuffer>,
    info: Uint8Array<ArrayBuffer>,
    associated_data: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  PrivateKey_Serialize: (obj: Wrapper<PrivateKey>) => Uint8Array<ArrayBuffer>;
  PrivateKey_Sign: (
    key: Wrapper<PrivateKey>,
    message: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ProfileKeyCiphertext_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ProfileKeyCommitment_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ProfileKeyCredentialPresentation_CheckValidContents: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Serialized<ProfileKeyCiphertext>;
  ProfileKeyCredentialPresentation_GetUuidCiphertext: (
    presentation_bytes: Uint8Array<ArrayBuffer>
  ) => Serialized<UuidCiphertext>;
  ProfileKeyCredentialRequestContext_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ProfileKeyCredentialRequestContext_GetRequest: (
    context: Serialized<ProfileKeyCredentialRequestContext>
  ) => Serialized<ProfileKeyCredentialRequest>;
  ProfileKeyCredentialRequest_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ProfileKey_CheckValidContents: (buffer: Uint8Array<ArrayBuffer>) => void;
  ProfileKey_DeriveAccessKey: (
    profile_key: Serialized<ProfileKey>
  ) => Uint8Array<ArrayBuffer>;
  ProfileKey_GetCommitment: (
    profile_key: Serialized<ProfileKey>,
    user_id: Uint8Array<ArrayBuffer>
  ) => Serialized<ProfileKeyCommitment>;
  ProfileKey_GetProfileKeyVersion: (
    profile_key: Serialized<ProfileKey>,
    user_id: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ProtocolAddress_DeviceId: (obj: Wrapper<ProtocolAddress>) => number;
  ProtocolAddress_Name: (obj: Wrapper<ProtocolAddress>) => string;
  ProtocolAddress_New: (name: string, device_id: number) => ProtocolAddress;
  ProvisioningChatConnection_connect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>
  ) => CancellablePromise<ProvisioningChatConnection>;
  ProvisioningChatConnection_disconnect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<ProvisioningChatConnection>
  ) => CancellablePromise<void>;
  ProvisioningChatConnection_info: (
    chat: Wrapper<ProvisioningChatConnection>
  ) => ChatConnectionInfo;
  ProvisioningChatConnection_init_listener: (
    chat: Wrapper<ProvisioningChatConnection>,
    listener: ProvisioningListener
  ) => void;
  PublicKey_Deserialize: (data: Uint8Array<ArrayBuffer>) => PublicKey;
  PublicKey_Equals: (
    lhs: Wrapper<PublicKey>,
    rhs: Wrapper<PublicKey>
  ) => boolean;
  PublicKey_GetPublicKeyBytes: (
    obj: Wrapper<PublicKey>
  ) => Uint8Array<ArrayBuffer>;
  PublicKey_HpkeSeal: (
    pk: Wrapper<PublicKey>,
    plaintext: Uint8Array<ArrayBuffer>,
    info: Uint8Array<ArrayBuffer>,
    associated_data: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  PublicKey_Serialize: (obj: Wrapper<PublicKey>) => Uint8Array<ArrayBuffer>;
  PublicKey_Verify: (
    key: Wrapper<PublicKey>,
    message: Uint8Array<ArrayBuffer>,
    signature: Uint8Array<ArrayBuffer>
  ) => boolean;
  ReceiptCredentialPresentation_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ReceiptCredentialPresentation_GetReceiptExpirationTime: (
    presentation: Serialized<ReceiptCredentialPresentation>
  ) => Timestamp;
  ReceiptCredentialPresentation_GetReceiptLevel: (
    presentation: Serialized<ReceiptCredentialPresentation>
  ) => bigint;
  ReceiptCredentialPresentation_GetReceiptSerial: (
    presentation: Serialized<ReceiptCredentialPresentation>
  ) => Uint8Array<ArrayBuffer>;
  ReceiptCredentialRequestContext_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ReceiptCredentialRequestContext_GetRequest: (
    request_context: Serialized<ReceiptCredentialRequestContext>
  ) => Serialized<ReceiptCredentialRequest>;
  ReceiptCredentialRequest_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ReceiptCredentialResponse_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ReceiptCredential_CheckValidContents: (
    buffer: Uint8Array<ArrayBuffer>
  ) => void;
  ReceiptCredential_GetReceiptExpirationTime: (
    receipt_credential: Serialized<ReceiptCredential>
  ) => Timestamp;
  ReceiptCredential_GetReceiptLevel: (
    receipt_credential: Serialized<ReceiptCredential>
  ) => bigint;
  RegisterAccountRequest_Create: () => RegisterAccountRequest;
  RegisterAccountRequest_SetAccountPassword: (
    register_account: Wrapper<RegisterAccountRequest>,
    account_password: string
  ) => void;
  RegisterAccountRequest_SetIdentityPqLastResortPreKey: (
    register_account: Wrapper<RegisterAccountRequest>,
    identity_type: number,
    pq_last_resort_pre_key: SignedPublicPreKey
  ) => void;
  RegisterAccountRequest_SetIdentityPublicKey: (
    register_account: Wrapper<RegisterAccountRequest>,
    identity_type: number,
    identity_key: Wrapper<PublicKey>
  ) => void;
  RegisterAccountRequest_SetIdentitySignedPreKey: (
    register_account: Wrapper<RegisterAccountRequest>,
    identity_type: number,
    signed_pre_key: SignedPublicPreKey
  ) => void;
  RegisterAccountRequest_SetSkipDeviceTransfer: (
    register_account: Wrapper<RegisterAccountRequest>
  ) => void;
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds: (
    response: Wrapper<RegisterAccountResponse>
  ) => bigint | null;
  RegisterAccountResponse_GetEntitlementBackupLevel: (
    response: Wrapper<RegisterAccountResponse>
  ) => bigint | null;
  RegisterAccountResponse_GetEntitlementBadges: (
    response: Wrapper<RegisterAccountResponse>
  ) => Array<RegisterResponseBadge>;
  RegisterAccountResponse_GetIdentity: (
    response: Wrapper<RegisterAccountResponse>,
    identity_type: number
  ) => Uint8Array<ArrayBuffer>;
  RegisterAccountResponse_GetNumber: (
    response: Wrapper<RegisterAccountResponse>
  ) => string;
  RegisterAccountResponse_GetReregistration: (
    response: Wrapper<RegisterAccountResponse>
  ) => boolean;
  RegisterAccountResponse_GetStorageCapable: (
    response: Wrapper<RegisterAccountResponse>
  ) => boolean;
  RegisterAccountResponse_GetUsernameHash: (
    response: Wrapper<RegisterAccountResponse>
  ) => Uint8Array<ArrayBuffer> | null;
  RegisterAccountResponse_GetUsernameLinkHandle: (
    response: Wrapper<RegisterAccountResponse>
  ) => Uuid | null;
  RegistrationAccountAttributes_Create: (
    recovery_password: Uint8Array<ArrayBuffer>,
    aci_registration_id: number,
    pni_registration_id: number,
    registration_lock: string | null,
    unidentified_access_key: Uint8Array<ArrayBuffer>,
    unrestricted_unidentified_access: boolean,
    capabilities: Array<string>,
    discoverable_by_phone_number: boolean
  ) => RegistrationAccountAttributes;
  RegistrationService_CheckSvr2Credentials: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    service: Wrapper<RegistrationService>,
    svr_tokens: Array<string>
  ) => CancellablePromise<CheckSvr2CredentialsResponse>;
  RegistrationService_CreateSession: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    create_session: RegistrationCreateSessionRequest,
    connect_chat: ConnectChatBridge
  ) => CancellablePromise<RegistrationService>;
  RegistrationService_RegisterAccount: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    service: Wrapper<RegistrationService>,
    register_account: Wrapper<RegisterAccountRequest>,
    account_attributes: Wrapper<RegistrationAccountAttributes>
  ) => CancellablePromise<RegisterAccountResponse>;
  RegistrationService_RegistrationSession: (
    service: Wrapper<RegistrationService>
  ) => RegistrationSession;
  RegistrationService_RequestVerificationCode: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    service: Wrapper<RegistrationService>,
    transport: string,
    client: string,
    languages: Array<string>
  ) => CancellablePromise<void>;
  RegistrationService_ReregisterAccount: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connect_chat: ConnectChatBridge,
    number: string,
    register_account: Wrapper<RegisterAccountRequest>,
    account_attributes: Wrapper<RegistrationAccountAttributes>
  ) => CancellablePromise<RegisterAccountResponse>;
  RegistrationService_ResumeSession: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    session_id: string,
    number: string,
    connect_chat: ConnectChatBridge
  ) => CancellablePromise<RegistrationService>;
  RegistrationService_SessionId: (
    service: Wrapper<RegistrationService>
  ) => string;
  RegistrationService_SubmitCaptcha: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    service: Wrapper<RegistrationService>,
    captcha_value: string
  ) => CancellablePromise<void>;
  RegistrationService_SubmitVerificationCode: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    service: Wrapper<RegistrationService>,
    code: string
  ) => CancellablePromise<void>;
  RegistrationSession_GetAllowedToRequestCode: (
    session: Wrapper<RegistrationSession>
  ) => boolean;
  RegistrationSession_GetNextCallSeconds: (
    session: Wrapper<RegistrationSession>
  ) => number | null;
  RegistrationSession_GetNextSmsSeconds: (
    session: Wrapper<RegistrationSession>
  ) => number | null;
  RegistrationSession_GetNextVerificationAttemptSeconds: (
    session: Wrapper<RegistrationSession>
  ) => number | null;
  RegistrationSession_GetRequestedInformation: (
    session: Wrapper<RegistrationSession>
  ) => Array<ChallengeOption>;
  RegistrationSession_GetVerified: (
    session: Wrapper<RegistrationSession>
  ) => boolean;
  SanitizedMetadata_GetDataLen: (
    sanitized: Wrapper<SanitizedMetadata>
  ) => bigint;
  SanitizedMetadata_GetDataOffset: (
    sanitized: Wrapper<SanitizedMetadata>
  ) => bigint;
  SanitizedMetadata_GetMetadata: (
    sanitized: Wrapper<SanitizedMetadata>
  ) => Uint8Array<ArrayBuffer>;
  ScannableFingerprint_Compare: (
    fprint1: Uint8Array<ArrayBuffer>,
    fprint2: Uint8Array<ArrayBuffer>
  ) => boolean;
  SealedSenderDecryptionResult_GetDeviceId: (
    obj: Wrapper<SealedSenderDecryptionResult>
  ) => number;
  SealedSenderDecryptionResult_GetSenderE164: (
    obj: Wrapper<SealedSenderDecryptionResult>
  ) => string | null;
  SealedSenderDecryptionResult_GetSenderUuid: (
    obj: Wrapper<SealedSenderDecryptionResult>
  ) => string;
  SealedSenderDecryptionResult_Message: (
    obj: Wrapper<SealedSenderDecryptionResult>
  ) => Uint8Array<ArrayBuffer>;
  SealedSenderMultiRecipientMessage_Parse: (
    buffer: Uint8Array<ArrayBuffer>
  ) => SealedSenderMultiRecipientMessage;
  SealedSender_DecryptMessage: (
    message: Uint8Array<ArrayBuffer>,
    trust_root: Wrapper<PublicKey>,
    timestamp: Timestamp,
    local_e164: string | null,
    local_uuid: string,
    local_device_id: number,
    session_store: SessionStore,
    identity_store: IdentityKeyStore,
    prekey_store: PreKeyStore,
    signed_prekey_store: SignedPreKeyStore,
    kyber_prekey_store: KyberPreKeyStore
  ) => Promise<SealedSenderDecryptionResult>;
  SealedSender_DecryptToUsmc: (
    ctext: Uint8Array<ArrayBuffer>,
    identity_store: IdentityKeyStore
  ) => Promise<UnidentifiedSenderMessageContent>;
  SealedSender_Encrypt: (
    destination: Wrapper<ProtocolAddress>,
    content: Wrapper<UnidentifiedSenderMessageContent>,
    identity_key_store: IdentityKeyStore
  ) => Promise<Uint8Array<ArrayBuffer>>;
  SealedSender_MultiRecipientEncrypt: (
    recipients: Array<Wrapper<ProtocolAddress>>,
    recipient_sessions: Array<Wrapper<SessionRecord>>,
    excluded_recipients: Uint8Array<ArrayBuffer>,
    content: Wrapper<UnidentifiedSenderMessageContent>,
    identity_key_store: IdentityKeyStore
  ) => Promise<Uint8Array<ArrayBuffer>>;
  SealedSender_MultiRecipientMessageForSingleRecipient: (
    encoded_multi_recipient_message: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  SecureValueRecoveryForBackups_CreateNewBackupChain: (
    environment: number,
    backup_key: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  SecureValueRecoveryForBackups_RemoveBackup: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<void>;
  SecureValueRecoveryForBackups_RestoreBackupFromServer: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    backup_key: Uint8Array<ArrayBuffer>,
    metadata: Uint8Array<ArrayBuffer>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<BackupRestoreResponse>;
  SecureValueRecoveryForBackups_StoreBackup: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    backup_key: Uint8Array<ArrayBuffer>,
    previous_secret_data: Uint8Array<ArrayBuffer>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<BackupStoreResponse>;
  SenderCertificate_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => SenderCertificate;
  SenderCertificate_GetCertificate: (
    obj: Wrapper<SenderCertificate>
  ) => Uint8Array<ArrayBuffer>;
  SenderCertificate_GetDeviceId: (obj: Wrapper<SenderCertificate>) => number;
  SenderCertificate_GetExpiration: (
    obj: Wrapper<SenderCertificate>
  ) => Timestamp;
  SenderCertificate_GetKey: (obj: Wrapper<SenderCertificate>) => PublicKey;
  SenderCertificate_GetSenderE164: (
    obj: Wrapper<SenderCertificate>
  ) => string | null;
  SenderCertificate_GetSenderUuid: (obj: Wrapper<SenderCertificate>) => string;
  SenderCertificate_GetSerialized: (
    obj: Wrapper<SenderCertificate>
  ) => Uint8Array<ArrayBuffer>;
  SenderCertificate_GetServerCertificate: (
    cert: Wrapper<SenderCertificate>
  ) => ServerCertificate;
  SenderCertificate_GetSignature: (
    obj: Wrapper<SenderCertificate>
  ) => Uint8Array<ArrayBuffer>;
  SenderCertificate_New: (
    sender_uuid: string,
    sender_e164: string | null,
    sender_device_id: number,
    sender_key: Wrapper<PublicKey>,
    expiration: Timestamp,
    signer_cert: Wrapper<ServerCertificate>,
    signer_key: Wrapper<PrivateKey>
  ) => SenderCertificate;
  SenderCertificate_Validate: (
    cert: Wrapper<SenderCertificate>,
    trust_roots: Array<Wrapper<PublicKey>>,
    time: Timestamp
  ) => boolean;
  SenderKeyDistributionMessage_Create: (
    sender: Wrapper<ProtocolAddress>,
    distribution_id: Uuid,
    store: SenderKeyStore
  ) => Promise<SenderKeyDistributionMessage>;
  SenderKeyDistributionMessage_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => SenderKeyDistributionMessage;
  SenderKeyDistributionMessage_GetChainId: (
    obj: Wrapper<SenderKeyDistributionMessage>
  ) => number;
  SenderKeyDistributionMessage_GetChainKey: (
    obj: Wrapper<SenderKeyDistributionMessage>
  ) => Uint8Array<ArrayBuffer>;
  SenderKeyDistributionMessage_GetDistributionId: (
    obj: Wrapper<SenderKeyDistributionMessage>
  ) => Uuid;
  SenderKeyDistributionMessage_GetIteration: (
    obj: Wrapper<SenderKeyDistributionMessage>
  ) => number;
  SenderKeyDistributionMessage_New: (
    message_version: number,
    distribution_id: Uuid,
    chain_id: number,
    iteration: number,
    chainkey: Uint8Array<ArrayBuffer>,
    pk: Wrapper<PublicKey>
  ) => SenderKeyDistributionMessage;
  SenderKeyDistributionMessage_Process: (
    sender: Wrapper<ProtocolAddress>,
    sender_key_distribution_message: Wrapper<SenderKeyDistributionMessage>,
    store: SenderKeyStore
  ) => Promise<void>;
  SenderKeyDistributionMessage_Serialize: (
    obj: Wrapper<SenderKeyDistributionMessage>
  ) => Uint8Array<ArrayBuffer>;
  SenderKeyMessage_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => SenderKeyMessage;
  SenderKeyMessage_GetChainId: (obj: Wrapper<SenderKeyMessage>) => number;
  SenderKeyMessage_GetCipherText: (
    obj: Wrapper<SenderKeyMessage>
  ) => Uint8Array<ArrayBuffer>;
  SenderKeyMessage_GetDistributionId: (obj: Wrapper<SenderKeyMessage>) => Uuid;
  SenderKeyMessage_GetIteration: (obj: Wrapper<SenderKeyMessage>) => number;
  SenderKeyMessage_New: (
    message_version: number,
    distribution_id: Uuid,
    chain_id: number,
    iteration: number,
    ciphertext: Uint8Array<ArrayBuffer>,
    pk: Wrapper<PrivateKey>
  ) => SenderKeyMessage;
  SenderKeyMessage_Serialize: (
    obj: Wrapper<SenderKeyMessage>
  ) => Uint8Array<ArrayBuffer>;
  SenderKeyMessage_VerifySignature: (
    skm: Wrapper<SenderKeyMessage>,
    pubkey: Wrapper<PublicKey>
  ) => boolean;
  SenderKeyRecord_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => SenderKeyRecord;
  SenderKeyRecord_Serialize: (
    obj: Wrapper<SenderKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  ServerCertificate_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => ServerCertificate;
  ServerCertificate_GetCertificate: (
    obj: Wrapper<ServerCertificate>
  ) => Uint8Array<ArrayBuffer>;
  ServerCertificate_GetKey: (obj: Wrapper<ServerCertificate>) => PublicKey;
  ServerCertificate_GetKeyId: (obj: Wrapper<ServerCertificate>) => number;
  ServerCertificate_GetSerialized: (
    obj: Wrapper<ServerCertificate>
  ) => Uint8Array<ArrayBuffer>;
  ServerCertificate_GetSignature: (
    obj: Wrapper<ServerCertificate>
  ) => Uint8Array<ArrayBuffer>;
  ServerCertificate_New: (
    key_id: number,
    server_key: Wrapper<PublicKey>,
    trust_root: Wrapper<PrivateKey>
  ) => ServerCertificate;
  ServerMessageAck_SendStatus: (
    ack: Wrapper<ServerMessageAck>,
    status: number
  ) => void;
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic: (
    server_public_params: Wrapper<ServerPublicParams>,
    randomness: Uint8Array<ArrayBuffer>,
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential_with_pni_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic: (
    server_public_params: Wrapper<ServerPublicParams>,
    randomness: Uint8Array<ArrayBuffer>,
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ExpiringProfileKeyCredential>
  ) => Uint8Array<ArrayBuffer>;
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic: (
    server_public_params: Wrapper<ServerPublicParams>,
    randomness: Uint8Array<ArrayBuffer>,
    user_id: Uint8Array<ArrayBuffer>,
    profile_key: Serialized<ProfileKey>
  ) => Serialized<ProfileKeyCredentialRequestContext>;
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic: (
    server_public_params: Wrapper<ServerPublicParams>,
    randomness: Uint8Array<ArrayBuffer>,
    receipt_credential: Serialized<ReceiptCredential>
  ) => Serialized<ReceiptCredentialPresentation>;
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic: (
    server_public_params: Wrapper<ServerPublicParams>,
    randomness: Uint8Array<ArrayBuffer>,
    receipt_serial: Uint8Array<ArrayBuffer>
  ) => Serialized<ReceiptCredentialRequestContext>;
  ServerPublicParams_Deserialize: (
    buffer: Uint8Array<ArrayBuffer>
  ) => ServerPublicParams;
  ServerPublicParams_GetEndorsementPublicKey: (
    params: Wrapper<ServerPublicParams>
  ) => Uint8Array<ArrayBuffer>;
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId: (
    params: Wrapper<ServerPublicParams>,
    aci: Uint8Array<ArrayBuffer>,
    pni: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp,
    auth_credential_with_pni_response_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ServerPublicParams_ReceiveExpiringProfileKeyCredential: (
    server_public_params: Wrapper<ServerPublicParams>,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ExpiringProfileKeyCredentialResponse>,
    current_time_in_seconds: Timestamp
  ) => Serialized<ExpiringProfileKeyCredential>;
  ServerPublicParams_ReceiveReceiptCredential: (
    server_public_params: Wrapper<ServerPublicParams>,
    request_context: Serialized<ReceiptCredentialRequestContext>,
    response: Serialized<ReceiptCredentialResponse>
  ) => Serialized<ReceiptCredential>;
  ServerPublicParams_Serialize: (
    handle: Wrapper<ServerPublicParams>
  ) => Uint8Array<ArrayBuffer>;
  ServerPublicParams_VerifySignature: (
    server_public_params: Wrapper<ServerPublicParams>,
    message: Uint8Array<ArrayBuffer>,
    notary_signature: Uint8Array<ArrayBuffer>
  ) => void;
  ServerSecretParams_Deserialize: (
    buffer: Uint8Array<ArrayBuffer>
  ) => ServerSecretParams;
  ServerSecretParams_GenerateDeterministic: (
    randomness: Uint8Array<ArrayBuffer>
  ) => ServerSecretParams;
  ServerSecretParams_GetPublicParams: (
    params: Wrapper<ServerSecretParams>
  ) => ServerPublicParams;
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic: (
    server_secret_params: Wrapper<ServerSecretParams>,
    randomness: Uint8Array<ArrayBuffer>,
    aci: Uint8Array<ArrayBuffer>,
    pni: Uint8Array<ArrayBuffer>,
    redemption_time: Timestamp
  ) => Uint8Array<ArrayBuffer>;
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic: (
    server_secret_params: Wrapper<ServerSecretParams>,
    randomness: Uint8Array<ArrayBuffer>,
    request: Serialized<ProfileKeyCredentialRequest>,
    user_id: Uint8Array<ArrayBuffer>,
    commitment: Serialized<ProfileKeyCommitment>,
    expiration_in_seconds: Timestamp
  ) => Serialized<ExpiringProfileKeyCredentialResponse>;
  ServerSecretParams_IssueReceiptCredentialDeterministic: (
    server_secret_params: Wrapper<ServerSecretParams>,
    randomness: Uint8Array<ArrayBuffer>,
    request: Serialized<ReceiptCredentialRequest>,
    receipt_expiration_time: Timestamp,
    receipt_level: bigint
  ) => Serialized<ReceiptCredentialResponse>;
  ServerSecretParams_Serialize: (
    handle: Wrapper<ServerSecretParams>
  ) => Uint8Array<ArrayBuffer>;
  ServerSecretParams_SignDeterministic: (
    params: Wrapper<ServerSecretParams>,
    randomness: Uint8Array<ArrayBuffer>,
    message: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ServerSecretParams_VerifyAuthCredentialPresentation: (
    server_secret_params: Wrapper<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: Uint8Array<ArrayBuffer>,
    current_time_in_seconds: Timestamp
  ) => void;
  ServerSecretParams_VerifyProfileKeyCredentialPresentation: (
    server_secret_params: Wrapper<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: Uint8Array<ArrayBuffer>,
    current_time_in_seconds: Timestamp
  ) => void;
  ServerSecretParams_VerifyReceiptCredentialPresentation: (
    server_secret_params: Wrapper<ServerSecretParams>,
    presentation: Serialized<ReceiptCredentialPresentation>
  ) => void;
  ServiceId_ParseFromServiceIdBinary: (
    input: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ServiceId_ParseFromServiceIdString: (
    input: string
  ) => Uint8Array<ArrayBuffer>;
  ServiceId_ServiceIdBinary: (
    value: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ServiceId_ServiceIdLog: (value: Uint8Array<ArrayBuffer>) => string;
  ServiceId_ServiceIdString: (value: Uint8Array<ArrayBuffer>) => string;
  SessionBuilder_ProcessPreKeyBundle: (
    bundle: Wrapper<PreKeyBundle>,
    protocol_address: Wrapper<ProtocolAddress>,
    local_address: Wrapper<ProtocolAddress>,
    session_store: SessionStore,
    identity_key_store: IdentityKeyStore,
    now: Timestamp
  ) => Promise<void>;
  SessionCipher_DecryptPreKeySignalMessage: (
    message: Wrapper<PreKeySignalMessage>,
    protocol_address: Wrapper<ProtocolAddress>,
    local_address: Wrapper<ProtocolAddress>,
    session_store: SessionStore,
    identity_key_store: IdentityKeyStore,
    prekey_store: PreKeyStore,
    signed_prekey_store: SignedPreKeyStore,
    kyber_prekey_store: KyberPreKeyStore
  ) => Promise<Uint8Array<ArrayBuffer>>;
  SessionCipher_DecryptSignalMessage: (
    message: Wrapper<SignalMessage>,
    protocol_address: Wrapper<ProtocolAddress>,
    local_address: Wrapper<ProtocolAddress>,
    session_store: SessionStore,
    identity_key_store: IdentityKeyStore
  ) => Promise<Uint8Array<ArrayBuffer>>;
  SessionCipher_EncryptMessage: (
    ptext: Uint8Array<ArrayBuffer>,
    protocol_address: Wrapper<ProtocolAddress>,
    local_address: Wrapper<ProtocolAddress>,
    session_store: SessionStore,
    identity_key_store: IdentityKeyStore,
    now: Timestamp
  ) => Promise<CiphertextMessage>;
  SessionRecord_ArchiveCurrentState: (
    session_record: Wrapper<SessionRecord>
  ) => void;
  SessionRecord_CurrentRatchetKeyMatches: (
    s: Wrapper<SessionRecord>,
    key: Wrapper<PublicKey>
  ) => boolean;
  SessionRecord_Deserialize: (data: Uint8Array<ArrayBuffer>) => SessionRecord;
  SessionRecord_GetLocalRegistrationId: (obj: Wrapper<SessionRecord>) => number;
  SessionRecord_GetRemoteRegistrationId: (
    obj: Wrapper<SessionRecord>
  ) => number;
  SessionRecord_HasUsableSenderChain: (
    s: Wrapper<SessionRecord>,
    require_pq_ratio: number,
    now: Timestamp
  ) => boolean;
  SessionRecord_Serialize: (
    obj: Wrapper<SessionRecord>
  ) => Uint8Array<ArrayBuffer>;
  SgxClientState_CompleteHandshake: (
    cli: Wrapper<SgxClientState>,
    handshake_received: Uint8Array<ArrayBuffer>
  ) => void;
  SgxClientState_EstablishedRecv: (
    cli: Wrapper<SgxClientState>,
    received_ciphertext: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  SgxClientState_EstablishedSend: (
    cli: Wrapper<SgxClientState>,
    plaintext_to_send: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  SgxClientState_InitialRequest: (
    obj: Wrapper<SgxClientState>
  ) => Uint8Array<ArrayBuffer>;
  SignalMedia_CheckAvailable: () => void;
  SignalMessage_Deserialize: (data: Uint8Array<ArrayBuffer>) => SignalMessage;
  SignalMessage_GetBody: (
    obj: Wrapper<SignalMessage>
  ) => Uint8Array<ArrayBuffer>;
  SignalMessage_GetCounter: (obj: Wrapper<SignalMessage>) => number;
  SignalMessage_GetMessageVersion: (obj: Wrapper<SignalMessage>) => number;
  SignalMessage_GetPqRatchet: (
    msg: Wrapper<SignalMessage>
  ) => Uint8Array<ArrayBuffer>;
  SignalMessage_GetSerialized: (
    obj: Wrapper<SignalMessage>
  ) => Uint8Array<ArrayBuffer>;
  SignalMessage_New: (
    message_version: number,
    mac_key: Uint8Array<ArrayBuffer>,
    sender_ratchet_key: Wrapper<PublicKey>,
    counter: number,
    previous_counter: number,
    ciphertext: Uint8Array<ArrayBuffer>,
    sender_identity_key: Wrapper<PublicKey>,
    receiver_identity_key: Wrapper<PublicKey>,
    pq_ratchet: Uint8Array<ArrayBuffer>
  ) => SignalMessage;
  SignedPreKeyRecord_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => SignedPreKeyRecord;
  SignedPreKeyRecord_GetId: (obj: Wrapper<SignedPreKeyRecord>) => number;
  SignedPreKeyRecord_GetPrivateKey: (
    obj: Wrapper<SignedPreKeyRecord>
  ) => PrivateKey;
  SignedPreKeyRecord_GetPublicKey: (
    obj: Wrapper<SignedPreKeyRecord>
  ) => PublicKey;
  SignedPreKeyRecord_GetSignature: (
    obj: Wrapper<SignedPreKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  SignedPreKeyRecord_GetTimestamp: (
    obj: Wrapper<SignedPreKeyRecord>
  ) => Timestamp;
  SignedPreKeyRecord_New: (
    id: number,
    timestamp: Timestamp,
    pub_key: Wrapper<PublicKey>,
    priv_key: Wrapper<PrivateKey>,
    signature: Uint8Array<ArrayBuffer>
  ) => SignedPreKeyRecord;
  SignedPreKeyRecord_Serialize: (
    obj: Wrapper<SignedPreKeyRecord>
  ) => Uint8Array<ArrayBuffer>;
  Svr2Client_New: (
    mrenclave: Uint8Array<ArrayBuffer>,
    attestation_msg: Uint8Array<ArrayBuffer>,
    current_timestamp: Timestamp
  ) => SgxClientState;
  Svr2_Delete: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<void>;
  Svr2_FinishBackup: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    session: Wrapper<Svr2BackupSession>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<void>;
  Svr2_Restore: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    pin: Uint8Array<ArrayBuffer>,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<[Uint8Array<ArrayBuffer>, number]>;
  Svr2_StartBackup: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    pin: Uint8Array<ArrayBuffer>,
    data: Uint8Array<ArrayBuffer>,
    max_tries: number,
    connection_manager: Wrapper<ConnectionManager>,
    username: string,
    password: string
  ) => CancellablePromise<Svr2BackupSession>;
  TESTING_BridgedStringMap_dump_to_json: (
    map: Wrapper<BridgedStringMap>
  ) => string;
  TESTING_CdsiLookupErrorConvert: (error_description: string) => void;
  TESTING_CdsiLookupResponseConvert: (
    asyncRuntime: Wrapper<TokioAsyncContext>
  ) => CancellablePromise<LookupResponse>;
  TESTING_ChatConnectErrorConvert: (error_description: string) => void;
  TESTING_ChatRequestGetBody: (
    request: Wrapper<HttpRequest>
  ) => Uint8Array<ArrayBuffer>;
  TESTING_ChatRequestGetHeaderNames: (
    request: Wrapper<HttpRequest>
  ) => Array<string>;
  TESTING_ChatRequestGetHeaderValue: (
    request: Wrapper<HttpRequest>,
    header_name: string
  ) => string;
  TESTING_ChatRequestGetMethod: (request: Wrapper<HttpRequest>) => string;
  TESTING_ChatRequestGetPath: (request: Wrapper<HttpRequest>) => string;
  TESTING_ChatResponseConvert: (body_present: boolean) => ChatResponse;
  TESTING_ChatSendErrorConvert: (error_description: string) => void;
  TESTING_ConnectionManager_isUsingProxy: (
    manager: Wrapper<ConnectionManager>
  ) => number;
  TESTING_ConnectionManager_newLocalOverride: (
    userAgent: string,
    chatPort: number,
    cdsiPort: number,
    svr2Port: number,
    svrBPort: number,
    rootCertificateDer: Uint8Array<ArrayBuffer>,
    http_version: number
  ) => ConnectionManager;
  TESTING_ConvertOptionalUuid: (present: boolean) => Uuid | null;
  TESTING_CreateOTP: (
    username: string,
    secret: Uint8Array<ArrayBuffer>
  ) => string;
  TESTING_CreateOTPFromBase64: (username: string, secret: string) => string;
  TESTING_EnableDeterministicRngForTesting: () => void;
  TESTING_ErrorOnBorrowAsync: (_input: null) => Promise<void>;
  TESTING_ErrorOnBorrowIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _input: null
  ) => CancellablePromise<void>;
  TESTING_ErrorOnBorrowSync: (_input: null) => void;
  TESTING_ErrorOnReturnAsync: (_needs_cleanup: null) => Promise<null>;
  TESTING_ErrorOnReturnIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _needs_cleanup: null
  ) => CancellablePromise<null>;
  TESTING_ErrorOnReturnSync: (_needs_cleanup: null) => null;
  TESTING_FakeChatConnection_Create: (
    tokio: Wrapper<TokioAsyncContext>,
    listener: ChatListener,
    grpc_overrides_joined_by_newlines: string,
    alerts_joined_by_newlines: string
  ) => FakeChatConnection;
  TESTING_FakeChatConnection_CreateProvisioning: (
    tokio: Wrapper<TokioAsyncContext>,
    listener: ProvisioningListener
  ) => FakeChatConnection;
  TESTING_FakeChatConnection_TakeAuthenticatedChat: (
    chat: Wrapper<FakeChatConnection>
  ) => AuthenticatedChatConnection;
  TESTING_FakeChatConnection_TakeProvisioningChat: (
    chat: Wrapper<FakeChatConnection>
  ) => ProvisioningChatConnection;
  TESTING_FakeChatConnection_TakeRemote: (
    chat: Wrapper<FakeChatConnection>
  ) => FakeChatRemoteEnd;
  TESTING_FakeChatConnection_TakeUnauthenticatedChat: (
    chat: Wrapper<FakeChatConnection>
  ) => UnauthenticatedChatConnection;
  TESTING_FakeChatRemoteEnd_BinprotoToJson: (
    name: string,
    input: Uint8Array<ArrayBuffer>
  ) => string;
  TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength: (
    len: number
  ) => Uint8Array<ArrayBuffer>;
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted: (
    chat: Wrapper<FakeChatRemoteEnd>
  ) => void;
  TESTING_FakeChatRemoteEnd_JsonToBinproto: (
    name: string,
    input: string
  ) => Uint8Array<ArrayBuffer>;
  TESTING_FakeChatRemoteEnd_NextGrpcMessage: (
    input: Uint8Array<ArrayBuffer>,
    offset: number
  ) => [number, number];
  TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<FakeChatRemoteEnd>
  ) => CancellablePromise<[HttpRequest, bigint] | null>;
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<FakeChatRemoteEnd>
  ) => CancellablePromise<[HttpRequest, bigint] | null>;
  TESTING_FakeChatRemoteEnd_SendRawServerRequest: (
    chat: Wrapper<FakeChatRemoteEnd>,
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  TESTING_FakeChatRemoteEnd_SendRawServerResponse: (
    chat: Wrapper<FakeChatRemoteEnd>,
    bytes: Uint8Array<ArrayBuffer>
  ) => void;
  TESTING_FakeChatRemoteEnd_SendServerGrpcResponse: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<FakeChatRemoteEnd>,
    response: Wrapper<FakeChatResponse>
  ) => CancellablePromise<void>;
  TESTING_FakeChatRemoteEnd_SendServerResponse: (
    chat: Wrapper<FakeChatRemoteEnd>,
    response: Wrapper<FakeChatResponse>
  ) => void;
  TESTING_FakeChatResponse_Create: (
    id: bigint,
    status: number,
    message: string,
    headers: Array<string>,
    body: Uint8Array<ArrayBuffer> | null
  ) => FakeChatResponse;
  TESTING_FakeChatServer_Create: () => FakeChatServer;
  TESTING_FakeChatServer_GetNextRemote: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    server: Wrapper<FakeChatServer>
  ) => CancellablePromise<FakeChatRemoteEnd>;
  TESTING_FakeRegistrationSession_CreateSession: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    create_session: RegistrationCreateSessionRequest,
    chat: Wrapper<FakeChatServer>
  ) => CancellablePromise<RegistrationService>;
  TESTING_FutureCancellationCounter_Create: (
    initial_value: number
  ) => TestingFutureCancellationCounter;
  TESTING_FutureCancellationCounter_WaitForCount: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    count: Wrapper<TestingFutureCancellationCounter>,
    target: number
  ) => CancellablePromise<void>;
  TESTING_FutureFailure: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _input: number
  ) => CancellablePromise<number>;
  TESTING_FutureIncrementOnCancel: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    _guard: TestingFutureCancellationGuard
  ) => CancellablePromise<void>;
  TESTING_FutureProducesOtherPointerType: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    input: string
  ) => CancellablePromise<OtherTestingHandleType>;
  TESTING_FutureProducesPointerType: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    input: number
  ) => CancellablePromise<TestingHandleType>;
  TESTING_FutureSuccess: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    input: number
  ) => CancellablePromise<number>;
  TESTING_InputStreamReadIntoZeroLengthSlice: (
    caps_alphabet_input: InputStream
  ) => Promise<Uint8Array<ArrayBuffer>>;
  TESTING_JoinStringArray: (array: Array<string>, join_with: string) => string;
  TESTING_KeyTransChatSendError: () => void;
  TESTING_KeyTransFatalVerificationFailure: () => void;
  TESTING_KeyTransNonFatalVerificationFailure: () => void;
  TESTING_KeyTransStoredAccountData: () => Uint8Array<ArrayBuffer>;
  TESTING_MyRemoteDeriveEnum_identity: (
    x: ArgFfiMyRemoteDeriveEnum
  ) => ReturnFfiMyRemoteDeriveEnum;
  TESTING_MyRemoteDeriveStruct_identity: (
    x: ArgFfiMyRemoteDeriveStruct
  ) => ReturnFfiMyRemoteDeriveStruct;
  TESTING_MySimpleTestEnum_identity: (
    x: ArgFfiMySimpleTestEnum
  ) => ReturnFfiMySimpleTestEnum;
  TESTING_MySimpleTestEnum_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: ArgFfiMySimpleTestEnum
  ) => CancellablePromise<ReturnFfiMySimpleTestEnum>;
  TESTING_MySimpleTestEnum_to_string: (x: ArgFfiMySimpleTestEnum) => string;
  TESTING_MyTestEnum_identity: (x: ArgFfiMyTestEnum) => ReturnFfiMyTestEnum;
  TESTING_MyTestEnum_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: ArgFfiMyTestEnum
  ) => CancellablePromise<ReturnFfiMyTestEnum>;
  TESTING_MyTestEnum_to_string: (x: ArgFfiMyTestEnum) => string;
  TESTING_MyTestPoint_identity: (x: ArgFfiMyTestPoint) => ReturnFfiMyTestPoint;
  TESTING_MyTestPoint_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: ArgFfiMyTestPoint
  ) => CancellablePromise<ReturnFfiMyTestPoint>;
  TESTING_MyTestPoint_to_string: (x: ArgFfiMyTestPoint) => string;
  TESTING_MyTestStruct_identity: (
    x: ArgFfiMyTestStruct
  ) => ReturnFfiMyTestStruct;
  TESTING_MyTestStruct_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: ArgFfiMyTestStruct
  ) => CancellablePromise<ReturnFfiMyTestStruct>;
  TESTING_MyTestStruct_to_string: (x: ArgFfiMyTestStruct) => string;
  TESTING_NonSuspendingBackgroundThreadRuntime_New: () => NonSuspendingBackgroundThreadRuntime;
  TESTING_OtherTestingHandleType_getValue: (
    handle: Wrapper<OtherTestingHandleType>
  ) => string;
  TESTING_PanicInBodyAsync: (_input: null) => Promise<void>;
  TESTING_PanicInBodyIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _input: null
  ) => CancellablePromise<void>;
  TESTING_PanicInBodySync: (_input: null) => void;
  TESTING_PanicOnBorrowAsync: (_input: null) => Promise<void>;
  TESTING_PanicOnBorrowIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _input: null
  ) => CancellablePromise<void>;
  TESTING_PanicOnBorrowSync: (_input: null) => void;
  TESTING_PanicOnLoadAsync: (
    _needs_cleanup: null,
    _input: null
  ) => Promise<void>;
  TESTING_PanicOnLoadIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _needs_cleanup: null,
    _input: null
  ) => CancellablePromise<void>;
  TESTING_PanicOnLoadSync: (_needs_cleanup: null, _input: null) => void;
  TESTING_PanicOnReturnAsync: (_needs_cleanup: null) => Promise<null>;
  TESTING_PanicOnReturnIo: (
    asyncRuntime: Wrapper<NonSuspendingBackgroundThreadRuntime>,
    _needs_cleanup: null
  ) => CancellablePromise<null>;
  TESTING_PanicOnReturnSync: (_needs_cleanup: null) => null;
  TESTING_ProcessBytestringArray: (
    input: Array<Uint8Array<ArrayBuffer>>
  ) => Array<Uint8Array<ArrayBuffer>>;
  TESTING_RegisterAccountResponse_CreateTestValue: () => RegisterAccountResponse;
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert: () => CheckSvr2CredentialsResponse;
  TESTING_RegistrationService_CreateSessionErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_RegisterAccountErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_ResumeSessionErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_SubmitVerificationErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationService_UpdateSessionErrorConvert: (
    error_description: string
  ) => void;
  TESTING_RegistrationSessionInfoConvert: () => RegistrationSession;
  TESTING_ReturnPair: () => [number, string];
  TESTING_ReturnStringArray: () => Array<string>;
  TESTING_RoundTripI32: (input: number) => number;
  TESTING_RoundTripU16: (input: number) => number;
  TESTING_RoundTripU32: (input: number) => number;
  TESTING_RoundTripU64: (input: bigint) => bigint;
  TESTING_RoundTripU8: (input: number) => number;
  TESTING_ServerMessageAck_Create: () => ServerMessageAck;
  TESTING_SetDeviceNameTests: () => Array<
    GrpcTestCaseFfi<ReturnFfiSetDeviceNameArgs, ReturnFfiSetDeviceNameOut>
  >;
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly: (
    source_public_key: Wrapper<PublicKey>,
    signed_pre_key: SignedPublicPreKey
  ) => void;
  TESTING_TestingHandleType_getValue: (
    handle: Wrapper<TestingHandleType>
  ) => number;
  TESTING_TestingIntBox_Get: (my_int_box: Wrapper<TestingIntBox>) => number;
  TESTING_TestingIntBox_New: (value: number) => TestingIntBox;
  TESTING_TokioAsyncContext_FutureSuccessBytes: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    count: number
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  TESTING_TokioAsyncContext_NewSingleThreaded: () => TokioAsyncContext;
  TESTING_TokioAsyncFuture: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    input: number
  ) => CancellablePromise<number>;
  TESTING_conversion_Data_VecU8_identity: (
    x: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  TESTING_conversion_Data_VecU8_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  TESTING_conversion_Data_VecU8_to_string: (
    x: Uint8Array<ArrayBuffer>
  ) => string;
  TESTING_conversion_Data_identity: (
    x: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  TESTING_conversion_Data_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  TESTING_conversion_Data_to_string: (x: Uint8Array<ArrayBuffer>) => string;
  TESTING_conversion_ServiceId_identity: (
    x: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  TESTING_conversion_ServiceId_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  TESTING_conversion_ServiceId_to_string: (
    x: Uint8Array<ArrayBuffer>
  ) => string;
  TESTING_conversion_bool_identity: (x: boolean) => boolean;
  TESTING_conversion_bool_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: boolean
  ) => CancellablePromise<boolean>;
  TESTING_conversion_bool_to_string: (x: boolean) => string;
  TESTING_conversion_i32_identity: (x: number) => number;
  TESTING_conversion_i32_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: number
  ) => CancellablePromise<number>;
  TESTING_conversion_i32_to_string: (x: number) => string;
  TESTING_conversion_string_identity: (x: string) => string;
  TESTING_conversion_string_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: string
  ) => CancellablePromise<string>;
  TESTING_conversion_u16_identity: (x: number) => number;
  TESTING_conversion_u16_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: number
  ) => CancellablePromise<number>;
  TESTING_conversion_u16_to_string: (x: number) => string;
  TESTING_conversion_u8_identity: (x: number) => number;
  TESTING_conversion_u8_identity_async: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    x: number
  ) => CancellablePromise<number>;
  TESTING_conversion_u8_to_string: (x: number) => string;
  TestingSemaphore_AddPermits: (
    semaphore: Wrapper<TestingSemaphore>,
    permits: number
  ) => void;
  TestingSemaphore_New: (initial: number) => TestingSemaphore;
  TestingValueHolder_Get: (holder: Wrapper<TestingValueHolder>) => number;
  TestingValueHolder_New: (value: number) => TestingValueHolder;
  TokioAsyncContext_cancel: (
    context: Wrapper<TokioAsyncContext>,
    raw_cancellation_id: bigint
  ) => void;
  TokioAsyncContext_new: () => TokioAsyncContext;
  UnauthenticatedChatConnection_account_exists: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    account: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<boolean>;
  UnauthenticatedChatConnection_backup_delete_all: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    rng: RandomNumberGenerator
  ) => CancellablePromise<void>;
  UnauthenticatedChatConnection_backup_get_cdn_credentials: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    cdn: number,
    rng: RandomNumberGenerator
  ) => CancellablePromise<[[string, string]]>;
  UnauthenticatedChatConnection_backup_get_media_upload_form: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    upload_size: bigint,
    rng: RandomNumberGenerator
  ) => CancellablePromise<UploadForm>;
  UnauthenticatedChatConnection_backup_get_svrb_credentials: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    rng: RandomNumberGenerator
  ) => CancellablePromise<[string, string]>;
  UnauthenticatedChatConnection_backup_get_upload_form: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    upload_size: bigint,
    rng: RandomNumberGenerator
  ) => CancellablePromise<UploadForm>;
  UnauthenticatedChatConnection_backup_refresh: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    rng: RandomNumberGenerator
  ) => CancellablePromise<void>;
  UnauthenticatedChatConnection_backup_set_public_key: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    credential: Uint8Array<ArrayBuffer>,
    server_keys: Uint8Array<ArrayBuffer>,
    signing_key: Wrapper<PrivateKey>,
    rng: RandomNumberGenerator
  ) => CancellablePromise<void>;
  UnauthenticatedChatConnection_connect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    connection_manager: Wrapper<ConnectionManager>,
    languages: Array<string>
  ) => CancellablePromise<UnauthenticatedChatConnection>;
  UnauthenticatedChatConnection_disconnect: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>
  ) => CancellablePromise<void>;
  UnauthenticatedChatConnection_get_pre_keys_access_key_auth: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    auth: Uint8Array<ArrayBuffer>,
    target: Uint8Array<ArrayBuffer>,
    device: number
  ) => CancellablePromise<PreKeysResponse>;
  UnauthenticatedChatConnection_get_pre_keys_group_auth: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    auth: Uint8Array<ArrayBuffer>,
    target: Uint8Array<ArrayBuffer>,
    device: number
  ) => CancellablePromise<PreKeysResponse>;
  UnauthenticatedChatConnection_get_pre_keys_unrestricted_auth: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    target: Uint8Array<ArrayBuffer>,
    device: number
  ) => CancellablePromise<PreKeysResponse>;
  UnauthenticatedChatConnection_info: (
    chat: Wrapper<UnauthenticatedChatConnection>
  ) => ChatConnectionInfo;
  UnauthenticatedChatConnection_init_listener: (
    chat: Wrapper<UnauthenticatedChatConnection>,
    listener: ChatListener
  ) => void;
  UnauthenticatedChatConnection_look_up_username_hash: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    hash: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uuid | null>;
  UnauthenticatedChatConnection_look_up_username_link: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    uuid: Uuid,
    entropy: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<[string, Uint8Array<ArrayBuffer>] | null>;
  UnauthenticatedChatConnection_send: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    http_request: Wrapper<HttpRequest>,
    timeout_millis: number
  ) => CancellablePromise<ChatResponse>;
  UnauthenticatedChatConnection_send_message: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    destination: Uint8Array<ArrayBuffer>,
    timestamp: Timestamp,
    device_ids: Uint32Array<ArrayBuffer>,
    registration_ids: Uint32Array<ArrayBuffer>,
    contents: Array<Uint8Array<ArrayBuffer>>,
    auth_kind: number,
    auth_buffer: Uint8Array<ArrayBuffer> | null,
    online_only: boolean,
    is_urgent: boolean
  ) => CancellablePromise<void>;
  UnauthenticatedChatConnection_send_multi_recipient_message: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    payload: Uint8Array<ArrayBuffer>,
    timestamp: Timestamp,
    auth: Uint8Array<ArrayBuffer> | null,
    online_only: boolean,
    is_urgent: boolean
  ) => CancellablePromise<Array<Uint8Array<ArrayBuffer>>>;
  UnauthenticatedChatConnection_send_raw_grpc: (
    asyncRuntime: Wrapper<TokioAsyncContext>,
    chat: Wrapper<UnauthenticatedChatConnection>,
    service: string,
    method: string,
    payload: Uint8Array<ArrayBuffer>
  ) => CancellablePromise<Uint8Array<ArrayBuffer>>;
  UnidentifiedSenderMessageContent_Deserialize: (
    data: Uint8Array<ArrayBuffer>
  ) => UnidentifiedSenderMessageContent;
  UnidentifiedSenderMessageContent_GetContentHint: (
    m: Wrapper<UnidentifiedSenderMessageContent>
  ) => number;
  UnidentifiedSenderMessageContent_GetContents: (
    obj: Wrapper<UnidentifiedSenderMessageContent>
  ) => Uint8Array<ArrayBuffer>;
  UnidentifiedSenderMessageContent_GetGroupId: (
    obj: Wrapper<UnidentifiedSenderMessageContent>
  ) => Uint8Array<ArrayBuffer> | null;
  UnidentifiedSenderMessageContent_GetMsgType: (
    m: Wrapper<UnidentifiedSenderMessageContent>
  ) => number;
  UnidentifiedSenderMessageContent_GetSenderCert: (
    m: Wrapper<UnidentifiedSenderMessageContent>
  ) => SenderCertificate;
  UnidentifiedSenderMessageContent_New: (
    message: Wrapper<CiphertextMessage>,
    sender: Wrapper<SenderCertificate>,
    content_hint: number,
    group_id: Uint8Array<ArrayBuffer> | null
  ) => UnidentifiedSenderMessageContent;
  UnidentifiedSenderMessageContent_Serialize: (
    obj: Wrapper<UnidentifiedSenderMessageContent>
  ) => Uint8Array<ArrayBuffer>;
  UsernameLink_Create: (
    username: string,
    entropy: Uint8Array<ArrayBuffer> | null
  ) => Uint8Array<ArrayBuffer>;
  UsernameLink_DecryptUsername: (
    entropy: Uint8Array<ArrayBuffer>,
    encrypted_username: Uint8Array<ArrayBuffer>
  ) => string;
  Username_CandidatesFrom: (
    nickname: string,
    min_len: number,
    max_len: number
  ) => Array<string>;
  Username_Hash: (username: string) => Uint8Array<ArrayBuffer>;
  Username_HashFromParts: (
    nickname: string,
    discriminator: string,
    min_len: number,
    max_len: number
  ) => Uint8Array<ArrayBuffer>;
  Username_Proof: (
    username: string,
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  Username_Verify: (
    proof: Uint8Array<ArrayBuffer>,
    hash: Uint8Array<ArrayBuffer>
  ) => void;
  UuidCiphertext_CheckValidContents: (buffer: Uint8Array<ArrayBuffer>) => void;
  ValidatingMac_Finalize: (mac: Wrapper<ValidatingMac>) => number;
  ValidatingMac_Initialize: (
    key: Uint8Array<ArrayBuffer>,
    chunk_size: number,
    digests: Uint8Array<ArrayBuffer>
  ) => ValidatingMac | null;
  ValidatingMac_Update: (
    mac: Wrapper<ValidatingMac>,
    bytes: Uint8Array<ArrayBuffer>,
    offset: number,
    length: number
  ) => number;
  WebpSanitizer_Sanitize: (input: SyncInputStream) => void;
  ZkCredentialKeyPair_CheckValidContents: (
    key_pair_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  ZkCredentialKeyPair_GenerateDeterministic: (
    randomness: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ZkCredentialKeyPair_GetPublicKey: (
    key_pair_bytes: Uint8Array<ArrayBuffer>
  ) => Uint8Array<ArrayBuffer>;
  ZkCredentialPublicKey_CheckValidContents: (
    public_key_bytes: Uint8Array<ArrayBuffer>
  ) => void;
  test_only_fn_returns_123: () => number;
  uuid_from_string: (string: string) => Uuid | null;
  uuid_new_v4: () => Uuid;
  uuid_to_string: (uuid: Uuid) => string;
};

const {
  registerErrors,
  initLogger,

  AccountEntropyPool_DeriveBackupKey,
  AccountEntropyPool_DeriveSvrKey,
  AccountEntropyPool_Generate,
  AccountEntropyPool_IsValid,
  Aes256GcmSiv_Decrypt,
  Aes256GcmSiv_Encrypt,
  Aes256GcmSiv_New,
  AuthCredentialPresentation_CheckValidContents,
  AuthCredentialPresentation_GetPniCiphertext,
  AuthCredentialPresentation_GetRedemptionTime,
  AuthCredentialPresentation_GetUuidCiphertext,
  AuthCredentialWithPniResponse_CheckValidContents,
  AuthCredentialWithPni_CheckValidContents,
  AuthenticatedChatConnection_connect,
  AuthenticatedChatConnection_disconnect,
  AuthenticatedChatConnection_get_upload_form,
  AuthenticatedChatConnection_info,
  AuthenticatedChatConnection_init_listener,
  AuthenticatedChatConnection_preconnect,
  AuthenticatedChatConnection_send,
  AuthenticatedChatConnection_send_message,
  AuthenticatedChatConnection_send_raw_grpc,
  AuthenticatedChatConnection_send_sync_message,
  AuthenticatedChatConnection_set_device_name,
  AvatarUploadCredentialPresentation_CheckValidContents,
  AvatarUploadCredentialPresentation_GetCm,
  AvatarUploadCredentialPresentation_GetRedemptionTime,
  AvatarUploadCredentialPresentation_Verify,
  AvatarUploadCredentialRequestContext_CheckValidContents,
  AvatarUploadCredentialRequestContext_GetRequest,
  AvatarUploadCredentialRequestContext_New,
  AvatarUploadCredentialRequestContext_ReceiveResponse,
  AvatarUploadCredentialRequest_CheckValidContents,
  AvatarUploadCredentialRequest_IssueDeterministic,
  AvatarUploadCredentialResponse_CheckValidContents,
  AvatarUploadCredential_CheckValidContents,
  AvatarUploadCredential_GetCm,
  AvatarUploadCredential_GetRedemptionTime,
  AvatarUploadCredential_PresentDeterministic,
  BackupAuthCredentialPresentation_CheckValidContents,
  BackupAuthCredentialPresentation_GetBackupId,
  BackupAuthCredentialPresentation_GetBackupLevel,
  BackupAuthCredentialPresentation_GetType,
  BackupAuthCredentialPresentation_Verify,
  BackupAuthCredentialRequestContext_CheckValidContents,
  BackupAuthCredentialRequestContext_GetRequest,
  BackupAuthCredentialRequestContext_New,
  BackupAuthCredentialRequestContext_ReceiveResponse,
  BackupAuthCredentialRequest_CheckValidContents,
  BackupAuthCredentialRequest_IssueDeterministic,
  BackupAuthCredentialResponse_CheckValidContents,
  BackupAuthCredential_CheckValidContents,
  BackupAuthCredential_GetBackupId,
  BackupAuthCredential_GetBackupLevel,
  BackupAuthCredential_GetType,
  BackupAuthCredential_PresentDeterministic,
  BackupJsonExporter_ExportFrames,
  BackupJsonExporter_Finish,
  BackupJsonExporter_GetInitialChunk,
  BackupJsonExporter_New,
  BackupKey_DeriveBackupId,
  BackupKey_DeriveEcKey,
  BackupKey_DeriveLocalBackupMetadataKey,
  BackupKey_DeriveMediaEncryptionKey,
  BackupKey_DeriveMediaId,
  BackupKey_DeriveThumbnailTransitEncryptionKey,
  BackupRestoreResponse_GetForwardSecrecyToken,
  BackupRestoreResponse_GetNextBackupSecretData,
  BackupStoreResponse_GetForwardSecrecyToken,
  BackupStoreResponse_GetNextBackupSecretData,
  BackupStoreResponse_GetOpaqueMetadata,
  BridgedStringMap_insert,
  BridgedStringMap_new,
  CallLinkAuthCredentialPresentation_CheckValidContents,
  CallLinkAuthCredentialPresentation_GetUserId,
  CallLinkAuthCredentialPresentation_Verify,
  CallLinkAuthCredentialResponse_CheckValidContents,
  CallLinkAuthCredentialResponse_IssueDeterministic,
  CallLinkAuthCredentialResponse_Receive,
  CallLinkAuthCredential_CheckValidContents,
  CallLinkAuthCredential_PresentDeterministic,
  CallLinkPublicParams_CheckValidContents,
  CallLinkSecretParams_CheckValidContents,
  CallLinkSecretParams_DecryptUserId,
  CallLinkSecretParams_DeriveFromRootKey,
  CallLinkSecretParams_EncryptUserId,
  CallLinkSecretParams_GetPublicParams,
  Cds2ClientState_New,
  CdsiLookup_complete,
  CdsiLookup_new,
  CdsiLookup_token,
  ChatConnectionInfo_description,
  ChatConnectionInfo_ip_version,
  ChatConnectionInfo_local_port,
  CiphertextMessage_FromPlaintextContent,
  CiphertextMessage_Serialize,
  CiphertextMessage_Type,
  ComparableBackup_GetComparableString,
  ComparableBackup_GetUnknownFields,
  ComparableBackup_ReadUnencrypted,
  ConnectionManager_clear_proxy,
  ConnectionManager_new,
  ConnectionManager_on_network_change,
  ConnectionManager_set_censorship_circumvention_enabled,
  ConnectionManager_set_invalid_proxy,
  ConnectionManager_set_ipv6_enabled,
  ConnectionManager_set_proxy,
  ConnectionManager_set_remote_config,
  ConnectionProxyConfig_new,
  CreateCallLinkCredentialPresentation_CheckValidContents,
  CreateCallLinkCredentialPresentation_Verify,
  CreateCallLinkCredentialRequestContext_CheckValidContents,
  CreateCallLinkCredentialRequestContext_GetRequest,
  CreateCallLinkCredentialRequestContext_NewDeterministic,
  CreateCallLinkCredentialRequestContext_ReceiveResponse,
  CreateCallLinkCredentialRequest_CheckValidContents,
  CreateCallLinkCredentialRequest_IssueDeterministic,
  CreateCallLinkCredentialResponse_CheckValidContents,
  CreateCallLinkCredential_CheckValidContents,
  CreateCallLinkCredential_PresentDeterministic,
  DecryptionErrorMessage_Deserialize,
  DecryptionErrorMessage_ExtractFromSerializedContent,
  DecryptionErrorMessage_ForOriginalMessage,
  DecryptionErrorMessage_GetDeviceId,
  DecryptionErrorMessage_GetRatchetKey,
  DecryptionErrorMessage_GetTimestamp,
  DecryptionErrorMessage_Serialize,
  DonationPermitDerivedKeyPair_CheckValidContents,
  DonationPermitDerivedKeyPair_ForExpiration,
  DonationPermitRequestContext_CheckValidContents,
  DonationPermitRequestContext_NewDeterministic,
  DonationPermitRequestContext_Receive,
  DonationPermitRequestContext_Request,
  DonationPermitRequest_CheckValidContents,
  DonationPermitRequest_Len,
  DonationPermitResponse_CheckValidContents,
  DonationPermitResponse_DefaultExpiration,
  DonationPermitResponse_GetExpiration,
  DonationPermitResponse_IssueDeterministic,
  DonationPermit_CheckValidContents,
  DonationPermit_Expiration,
  DonationPermit_SpendId,
  DonationPermit_Verify,
  ExpiringProfileKeyCredentialResponse_CheckValidContents,
  ExpiringProfileKeyCredential_CheckValidContents,
  ExpiringProfileKeyCredential_GetExpirationTime,
  Fingerprint_DisplayString,
  Fingerprint_New,
  Fingerprint_ScannableEncoding,
  GenericServerPublicParams_CheckValidContents,
  GenericServerSecretParams_CheckValidContents,
  GenericServerSecretParams_GenerateDeterministic,
  GenericServerSecretParams_GetPublicParams,
  GroupCipher_DecryptMessage,
  GroupCipher_EncryptMessage,
  GroupMasterKey_CheckValidContents,
  GroupPublicParams_CheckValidContents,
  GroupPublicParams_GetGroupIdentifier,
  GroupSecretParams_CheckValidContents,
  GroupSecretParams_DecryptBlobWithPadding,
  GroupSecretParams_DecryptProfileKey,
  GroupSecretParams_DecryptServiceId,
  GroupSecretParams_DeriveFromMasterKey,
  GroupSecretParams_EncryptBlobWithPaddingDeterministic,
  GroupSecretParams_EncryptProfileKey,
  GroupSecretParams_EncryptServiceId,
  GroupSecretParams_GenerateDeterministic,
  GroupSecretParams_GetMasterKey,
  GroupSecretParams_GetPublicParams,
  GroupSendDerivedKeyPair_CheckValidContents,
  GroupSendDerivedKeyPair_ForExpiration,
  GroupSendEndorsement_CallLinkParams_ToToken,
  GroupSendEndorsement_CheckValidContents,
  GroupSendEndorsement_Combine,
  GroupSendEndorsement_Remove,
  GroupSendEndorsement_ToToken,
  GroupSendEndorsementsResponse_CheckValidContents,
  GroupSendEndorsementsResponse_GetExpiration,
  GroupSendEndorsementsResponse_IssueDeterministic,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds,
  GroupSendFullToken_CheckValidContents,
  GroupSendFullToken_GetExpiration,
  GroupSendFullToken_Verify,
  GroupSendToken_CheckValidContents,
  GroupSendToken_ToFullToken,
  HKDF_DeriveSecrets,
  HsmEnclaveClient_CompleteHandshake,
  HsmEnclaveClient_EstablishedRecv,
  HsmEnclaveClient_EstablishedSend,
  HsmEnclaveClient_InitialRequest,
  HsmEnclaveClient_New,
  HttpRequest_add_header,
  HttpRequest_new,
  IdentityKeyPair_Deserialize,
  IdentityKeyPair_Serialize,
  IdentityKeyPair_SignAlternateIdentity,
  IdentityKey_VerifyAlternateIdentity,
  IncrementalMac_CalculateChunkSize,
  IncrementalMac_Finalize,
  IncrementalMac_Initialize,
  IncrementalMac_Update,
  KeyTransparency_AciSearchKey,
  KeyTransparency_Check,
  KeyTransparency_E164SearchKey,
  KeyTransparency_ResetDataField,
  KeyTransparency_UsernameHashSearchKey,
  KyberKeyPair_Generate,
  KyberKeyPair_GetPublicKey,
  KyberKeyPair_GetSecretKey,
  KyberPreKeyRecord_Deserialize,
  KyberPreKeyRecord_GetId,
  KyberPreKeyRecord_GetKeyPair,
  KyberPreKeyRecord_GetPublicKey,
  KyberPreKeyRecord_GetSecretKey,
  KyberPreKeyRecord_GetSignature,
  KyberPreKeyRecord_GetTimestamp,
  KyberPreKeyRecord_New,
  KyberPreKeyRecord_Serialize,
  KyberPublicKey_Deserialize,
  KyberPublicKey_Equals,
  KyberPublicKey_Serialize,
  KyberSecretKey_Deserialize,
  KyberSecretKey_Serialize,
  LookupRequest_addAciAndAccessKey,
  LookupRequest_addE164,
  LookupRequest_addPreviousE164,
  LookupRequest_new,
  LookupRequest_setToken,
  MessageBackupKey_FromAccountEntropyPool,
  MessageBackupKey_FromBackupKeyAndBackupId,
  MessageBackupKey_GetAesKey,
  MessageBackupKey_GetHmacKey,
  MessageBackupValidator_Validate,
  MinidumpToJSONString,
  Mp4Sanitizer_Sanitize,
  OnlineBackupValidator_AddFrame,
  OnlineBackupValidator_Finalize,
  OnlineBackupValidator_New,
  PinHash_AccessKey,
  PinHash_EncryptionKey,
  PinHash_FromSalt,
  PinHash_FromUsernameMrenclave,
  Pin_LocalHash,
  Pin_VerifyLocalHash,
  PlaintextContent_Deserialize,
  PlaintextContent_FromDecryptionErrorMessage,
  PlaintextContent_GetBody,
  PlaintextContent_Serialize,
  PreKeyBundle_GetDeviceId,
  PreKeyBundle_GetIdentityKey,
  PreKeyBundle_GetKyberPreKeyId,
  PreKeyBundle_GetKyberPreKeyPublic,
  PreKeyBundle_GetKyberPreKeySignature,
  PreKeyBundle_GetPreKeyId,
  PreKeyBundle_GetPreKeyPublic,
  PreKeyBundle_GetRegistrationId,
  PreKeyBundle_GetSignedPreKeyId,
  PreKeyBundle_GetSignedPreKeyPublic,
  PreKeyBundle_GetSignedPreKeySignature,
  PreKeyBundle_New,
  PreKeyRecord_Deserialize,
  PreKeyRecord_GetId,
  PreKeyRecord_GetPrivateKey,
  PreKeyRecord_GetPublicKey,
  PreKeyRecord_New,
  PreKeyRecord_Serialize,
  PreKeySignalMessage_Deserialize,
  PreKeySignalMessage_GetPreKeyId,
  PreKeySignalMessage_GetRegistrationId,
  PreKeySignalMessage_GetSignedPreKeyId,
  PreKeySignalMessage_GetVersion,
  PreKeySignalMessage_New,
  PreKeySignalMessage_Serialize,
  PrivateKey_Agree,
  PrivateKey_Deserialize,
  PrivateKey_Generate,
  PrivateKey_GetPublicKey,
  PrivateKey_HpkeOpen,
  PrivateKey_Serialize,
  PrivateKey_Sign,
  ProfileKeyCiphertext_CheckValidContents,
  ProfileKeyCommitment_CheckValidContents,
  ProfileKeyCredentialPresentation_CheckValidContents,
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext,
  ProfileKeyCredentialPresentation_GetUuidCiphertext,
  ProfileKeyCredentialRequestContext_CheckValidContents,
  ProfileKeyCredentialRequestContext_GetRequest,
  ProfileKeyCredentialRequest_CheckValidContents,
  ProfileKey_CheckValidContents,
  ProfileKey_DeriveAccessKey,
  ProfileKey_GetCommitment,
  ProfileKey_GetProfileKeyVersion,
  ProtocolAddress_DeviceId,
  ProtocolAddress_Name,
  ProtocolAddress_New,
  ProvisioningChatConnection_connect,
  ProvisioningChatConnection_disconnect,
  ProvisioningChatConnection_info,
  ProvisioningChatConnection_init_listener,
  PublicKey_Deserialize,
  PublicKey_Equals,
  PublicKey_GetPublicKeyBytes,
  PublicKey_HpkeSeal,
  PublicKey_Serialize,
  PublicKey_Verify,
  ReceiptCredentialPresentation_CheckValidContents,
  ReceiptCredentialPresentation_GetReceiptExpirationTime,
  ReceiptCredentialPresentation_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptSerial,
  ReceiptCredentialRequestContext_CheckValidContents,
  ReceiptCredentialRequestContext_GetRequest,
  ReceiptCredentialRequest_CheckValidContents,
  ReceiptCredentialResponse_CheckValidContents,
  ReceiptCredential_CheckValidContents,
  ReceiptCredential_GetReceiptExpirationTime,
  ReceiptCredential_GetReceiptLevel,
  RegisterAccountRequest_Create,
  RegisterAccountRequest_SetAccountPassword,
  RegisterAccountRequest_SetIdentityPqLastResortPreKey,
  RegisterAccountRequest_SetIdentityPublicKey,
  RegisterAccountRequest_SetIdentitySignedPreKey,
  RegisterAccountRequest_SetSkipDeviceTransfer,
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds,
  RegisterAccountResponse_GetEntitlementBackupLevel,
  RegisterAccountResponse_GetEntitlementBadges,
  RegisterAccountResponse_GetIdentity,
  RegisterAccountResponse_GetNumber,
  RegisterAccountResponse_GetReregistration,
  RegisterAccountResponse_GetStorageCapable,
  RegisterAccountResponse_GetUsernameHash,
  RegisterAccountResponse_GetUsernameLinkHandle,
  RegistrationAccountAttributes_Create,
  RegistrationService_CheckSvr2Credentials,
  RegistrationService_CreateSession,
  RegistrationService_RegisterAccount,
  RegistrationService_RegistrationSession,
  RegistrationService_RequestVerificationCode,
  RegistrationService_ReregisterAccount,
  RegistrationService_ResumeSession,
  RegistrationService_SessionId,
  RegistrationService_SubmitCaptcha,
  RegistrationService_SubmitVerificationCode,
  RegistrationSession_GetAllowedToRequestCode,
  RegistrationSession_GetNextCallSeconds,
  RegistrationSession_GetNextSmsSeconds,
  RegistrationSession_GetNextVerificationAttemptSeconds,
  RegistrationSession_GetRequestedInformation,
  RegistrationSession_GetVerified,
  SanitizedMetadata_GetDataLen,
  SanitizedMetadata_GetDataOffset,
  SanitizedMetadata_GetMetadata,
  ScannableFingerprint_Compare,
  SealedSenderDecryptionResult_GetDeviceId,
  SealedSenderDecryptionResult_GetSenderE164,
  SealedSenderDecryptionResult_GetSenderUuid,
  SealedSenderDecryptionResult_Message,
  SealedSenderMultiRecipientMessage_Parse,
  SealedSender_DecryptMessage,
  SealedSender_DecryptToUsmc,
  SealedSender_Encrypt,
  SealedSender_MultiRecipientEncrypt,
  SealedSender_MultiRecipientMessageForSingleRecipient,
  SecureValueRecoveryForBackups_CreateNewBackupChain,
  SecureValueRecoveryForBackups_RemoveBackup,
  SecureValueRecoveryForBackups_RestoreBackupFromServer,
  SecureValueRecoveryForBackups_StoreBackup,
  SenderCertificate_Deserialize,
  SenderCertificate_GetCertificate,
  SenderCertificate_GetDeviceId,
  SenderCertificate_GetExpiration,
  SenderCertificate_GetKey,
  SenderCertificate_GetSenderE164,
  SenderCertificate_GetSenderUuid,
  SenderCertificate_GetSerialized,
  SenderCertificate_GetServerCertificate,
  SenderCertificate_GetSignature,
  SenderCertificate_New,
  SenderCertificate_Validate,
  SenderKeyDistributionMessage_Create,
  SenderKeyDistributionMessage_Deserialize,
  SenderKeyDistributionMessage_GetChainId,
  SenderKeyDistributionMessage_GetChainKey,
  SenderKeyDistributionMessage_GetDistributionId,
  SenderKeyDistributionMessage_GetIteration,
  SenderKeyDistributionMessage_New,
  SenderKeyDistributionMessage_Process,
  SenderKeyDistributionMessage_Serialize,
  SenderKeyMessage_Deserialize,
  SenderKeyMessage_GetChainId,
  SenderKeyMessage_GetCipherText,
  SenderKeyMessage_GetDistributionId,
  SenderKeyMessage_GetIteration,
  SenderKeyMessage_New,
  SenderKeyMessage_Serialize,
  SenderKeyMessage_VerifySignature,
  SenderKeyRecord_Deserialize,
  SenderKeyRecord_Serialize,
  ServerCertificate_Deserialize,
  ServerCertificate_GetCertificate,
  ServerCertificate_GetKey,
  ServerCertificate_GetKeyId,
  ServerCertificate_GetSerialized,
  ServerCertificate_GetSignature,
  ServerCertificate_New,
  ServerMessageAck_SendStatus,
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic,
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic,
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic,
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic,
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic,
  ServerPublicParams_Deserialize,
  ServerPublicParams_GetEndorsementPublicKey,
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId,
  ServerPublicParams_ReceiveExpiringProfileKeyCredential,
  ServerPublicParams_ReceiveReceiptCredential,
  ServerPublicParams_Serialize,
  ServerPublicParams_VerifySignature,
  ServerSecretParams_Deserialize,
  ServerSecretParams_GenerateDeterministic,
  ServerSecretParams_GetPublicParams,
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic,
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic,
  ServerSecretParams_IssueReceiptCredentialDeterministic,
  ServerSecretParams_Serialize,
  ServerSecretParams_SignDeterministic,
  ServerSecretParams_VerifyAuthCredentialPresentation,
  ServerSecretParams_VerifyProfileKeyCredentialPresentation,
  ServerSecretParams_VerifyReceiptCredentialPresentation,
  ServiceId_ParseFromServiceIdBinary,
  ServiceId_ParseFromServiceIdString,
  ServiceId_ServiceIdBinary,
  ServiceId_ServiceIdLog,
  ServiceId_ServiceIdString,
  SessionBuilder_ProcessPreKeyBundle,
  SessionCipher_DecryptPreKeySignalMessage,
  SessionCipher_DecryptSignalMessage,
  SessionCipher_EncryptMessage,
  SessionRecord_ArchiveCurrentState,
  SessionRecord_CurrentRatchetKeyMatches,
  SessionRecord_Deserialize,
  SessionRecord_GetLocalRegistrationId,
  SessionRecord_GetRemoteRegistrationId,
  SessionRecord_HasUsableSenderChain,
  SessionRecord_Serialize,
  SgxClientState_CompleteHandshake,
  SgxClientState_EstablishedRecv,
  SgxClientState_EstablishedSend,
  SgxClientState_InitialRequest,
  SignalMedia_CheckAvailable,
  SignalMessage_Deserialize,
  SignalMessage_GetBody,
  SignalMessage_GetCounter,
  SignalMessage_GetMessageVersion,
  SignalMessage_GetPqRatchet,
  SignalMessage_GetSerialized,
  SignalMessage_New,
  SignedPreKeyRecord_Deserialize,
  SignedPreKeyRecord_GetId,
  SignedPreKeyRecord_GetPrivateKey,
  SignedPreKeyRecord_GetPublicKey,
  SignedPreKeyRecord_GetSignature,
  SignedPreKeyRecord_GetTimestamp,
  SignedPreKeyRecord_New,
  SignedPreKeyRecord_Serialize,
  Svr2Client_New,
  Svr2_Delete,
  Svr2_FinishBackup,
  Svr2_Restore,
  Svr2_StartBackup,
  TESTING_BridgedStringMap_dump_to_json,
  TESTING_CdsiLookupErrorConvert,
  TESTING_CdsiLookupResponseConvert,
  TESTING_ChatConnectErrorConvert,
  TESTING_ChatRequestGetBody,
  TESTING_ChatRequestGetHeaderNames,
  TESTING_ChatRequestGetHeaderValue,
  TESTING_ChatRequestGetMethod,
  TESTING_ChatRequestGetPath,
  TESTING_ChatResponseConvert,
  TESTING_ChatSendErrorConvert,
  TESTING_ConnectionManager_isUsingProxy,
  TESTING_ConnectionManager_newLocalOverride,
  TESTING_ConvertOptionalUuid,
  TESTING_CreateOTP,
  TESTING_CreateOTPFromBase64,
  TESTING_EnableDeterministicRngForTesting,
  TESTING_ErrorOnBorrowAsync,
  TESTING_ErrorOnBorrowIo,
  TESTING_ErrorOnBorrowSync,
  TESTING_ErrorOnReturnAsync,
  TESTING_ErrorOnReturnIo,
  TESTING_ErrorOnReturnSync,
  TESTING_FakeChatConnection_Create,
  TESTING_FakeChatConnection_CreateProvisioning,
  TESTING_FakeChatConnection_TakeAuthenticatedChat,
  TESTING_FakeChatConnection_TakeProvisioningChat,
  TESTING_FakeChatConnection_TakeRemote,
  TESTING_FakeChatConnection_TakeUnauthenticatedChat,
  TESTING_FakeChatRemoteEnd_BinprotoToJson,
  TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength,
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted,
  TESTING_FakeChatRemoteEnd_JsonToBinproto,
  TESTING_FakeChatRemoteEnd_NextGrpcMessage,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerResponse,
  TESTING_FakeChatRemoteEnd_SendServerGrpcResponse,
  TESTING_FakeChatRemoteEnd_SendServerResponse,
  TESTING_FakeChatResponse_Create,
  TESTING_FakeChatServer_Create,
  TESTING_FakeChatServer_GetNextRemote,
  TESTING_FakeRegistrationSession_CreateSession,
  TESTING_FutureCancellationCounter_Create,
  TESTING_FutureCancellationCounter_WaitForCount,
  TESTING_FutureFailure,
  TESTING_FutureIncrementOnCancel,
  TESTING_FutureProducesOtherPointerType,
  TESTING_FutureProducesPointerType,
  TESTING_FutureSuccess,
  TESTING_InputStreamReadIntoZeroLengthSlice,
  TESTING_JoinStringArray,
  TESTING_KeyTransChatSendError,
  TESTING_KeyTransFatalVerificationFailure,
  TESTING_KeyTransNonFatalVerificationFailure,
  TESTING_KeyTransStoredAccountData,
  TESTING_MyRemoteDeriveEnum_identity,
  TESTING_MyRemoteDeriveStruct_identity,
  TESTING_MySimpleTestEnum_identity,
  TESTING_MySimpleTestEnum_identity_async,
  TESTING_MySimpleTestEnum_to_string,
  TESTING_MyTestEnum_identity,
  TESTING_MyTestEnum_identity_async,
  TESTING_MyTestEnum_to_string,
  TESTING_MyTestPoint_identity,
  TESTING_MyTestPoint_identity_async,
  TESTING_MyTestPoint_to_string,
  TESTING_MyTestStruct_identity,
  TESTING_MyTestStruct_identity_async,
  TESTING_MyTestStruct_to_string,
  TESTING_NonSuspendingBackgroundThreadRuntime_New,
  TESTING_OtherTestingHandleType_getValue,
  TESTING_PanicInBodyAsync,
  TESTING_PanicInBodyIo,
  TESTING_PanicInBodySync,
  TESTING_PanicOnBorrowAsync,
  TESTING_PanicOnBorrowIo,
  TESTING_PanicOnBorrowSync,
  TESTING_PanicOnLoadAsync,
  TESTING_PanicOnLoadIo,
  TESTING_PanicOnLoadSync,
  TESTING_PanicOnReturnAsync,
  TESTING_PanicOnReturnIo,
  TESTING_PanicOnReturnSync,
  TESTING_ProcessBytestringArray,
  TESTING_RegisterAccountResponse_CreateTestValue,
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert,
  TESTING_RegistrationService_CreateSessionErrorConvert,
  TESTING_RegistrationService_RegisterAccountErrorConvert,
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert,
  TESTING_RegistrationService_ResumeSessionErrorConvert,
  TESTING_RegistrationService_SubmitVerificationErrorConvert,
  TESTING_RegistrationService_UpdateSessionErrorConvert,
  TESTING_RegistrationSessionInfoConvert,
  TESTING_ReturnPair,
  TESTING_ReturnStringArray,
  TESTING_RoundTripI32,
  TESTING_RoundTripU16,
  TESTING_RoundTripU32,
  TESTING_RoundTripU64,
  TESTING_RoundTripU8,
  TESTING_ServerMessageAck_Create,
  TESTING_SetDeviceNameTests,
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly,
  TESTING_TestingHandleType_getValue,
  TESTING_TestingIntBox_Get,
  TESTING_TestingIntBox_New,
  TESTING_TokioAsyncContext_FutureSuccessBytes,
  TESTING_TokioAsyncContext_NewSingleThreaded,
  TESTING_TokioAsyncFuture,
  TESTING_conversion_Data_VecU8_identity,
  TESTING_conversion_Data_VecU8_identity_async,
  TESTING_conversion_Data_VecU8_to_string,
  TESTING_conversion_Data_identity,
  TESTING_conversion_Data_identity_async,
  TESTING_conversion_Data_to_string,
  TESTING_conversion_ServiceId_identity,
  TESTING_conversion_ServiceId_identity_async,
  TESTING_conversion_ServiceId_to_string,
  TESTING_conversion_bool_identity,
  TESTING_conversion_bool_identity_async,
  TESTING_conversion_bool_to_string,
  TESTING_conversion_i32_identity,
  TESTING_conversion_i32_identity_async,
  TESTING_conversion_i32_to_string,
  TESTING_conversion_string_identity,
  TESTING_conversion_string_identity_async,
  TESTING_conversion_u16_identity,
  TESTING_conversion_u16_identity_async,
  TESTING_conversion_u16_to_string,
  TESTING_conversion_u8_identity,
  TESTING_conversion_u8_identity_async,
  TESTING_conversion_u8_to_string,
  TestingSemaphore_AddPermits,
  TestingSemaphore_New,
  TestingValueHolder_Get,
  TestingValueHolder_New,
  TokioAsyncContext_cancel,
  TokioAsyncContext_new,
  UnauthenticatedChatConnection_account_exists,
  UnauthenticatedChatConnection_backup_delete_all,
  UnauthenticatedChatConnection_backup_get_cdn_credentials,
  UnauthenticatedChatConnection_backup_get_media_upload_form,
  UnauthenticatedChatConnection_backup_get_svrb_credentials,
  UnauthenticatedChatConnection_backup_get_upload_form,
  UnauthenticatedChatConnection_backup_refresh,
  UnauthenticatedChatConnection_backup_set_public_key,
  UnauthenticatedChatConnection_connect,
  UnauthenticatedChatConnection_disconnect,
  UnauthenticatedChatConnection_get_pre_keys_access_key_auth,
  UnauthenticatedChatConnection_get_pre_keys_group_auth,
  UnauthenticatedChatConnection_get_pre_keys_unrestricted_auth,
  UnauthenticatedChatConnection_info,
  UnauthenticatedChatConnection_init_listener,
  UnauthenticatedChatConnection_look_up_username_hash,
  UnauthenticatedChatConnection_look_up_username_link,
  UnauthenticatedChatConnection_send,
  UnauthenticatedChatConnection_send_message,
  UnauthenticatedChatConnection_send_multi_recipient_message,
  UnauthenticatedChatConnection_send_raw_grpc,
  UnidentifiedSenderMessageContent_Deserialize,
  UnidentifiedSenderMessageContent_GetContentHint,
  UnidentifiedSenderMessageContent_GetContents,
  UnidentifiedSenderMessageContent_GetGroupId,
  UnidentifiedSenderMessageContent_GetMsgType,
  UnidentifiedSenderMessageContent_GetSenderCert,
  UnidentifiedSenderMessageContent_New,
  UnidentifiedSenderMessageContent_Serialize,
  UsernameLink_Create,
  UsernameLink_DecryptUsername,
  Username_CandidatesFrom,
  Username_Hash,
  Username_HashFromParts,
  Username_Proof,
  Username_Verify,
  UuidCiphertext_CheckValidContents,
  ValidatingMac_Finalize,
  ValidatingMac_Initialize,
  ValidatingMac_Update,
  WebpSanitizer_Sanitize,
  ZkCredentialKeyPair_CheckValidContents,
  ZkCredentialKeyPair_GenerateDeterministic,
  ZkCredentialKeyPair_GetPublicKey,
  ZkCredentialPublicKey_CheckValidContents,
  test_only_fn_returns_123,
  uuid_from_string,
  uuid_new_v4,
  uuid_to_string,
} = load(`${import.meta.dirname}/../`) as NativeFunctions;

export {
  registerErrors,
  initLogger,
  AccountEntropyPool_DeriveBackupKey,
  AccountEntropyPool_DeriveSvrKey,
  AccountEntropyPool_Generate,
  AccountEntropyPool_IsValid,
  Aes256GcmSiv_Decrypt,
  Aes256GcmSiv_Encrypt,
  Aes256GcmSiv_New,
  AuthCredentialPresentation_CheckValidContents,
  AuthCredentialPresentation_GetPniCiphertext,
  AuthCredentialPresentation_GetRedemptionTime,
  AuthCredentialPresentation_GetUuidCiphertext,
  AuthCredentialWithPniResponse_CheckValidContents,
  AuthCredentialWithPni_CheckValidContents,
  AuthenticatedChatConnection_connect,
  AuthenticatedChatConnection_disconnect,
  AuthenticatedChatConnection_get_upload_form,
  AuthenticatedChatConnection_info,
  AuthenticatedChatConnection_init_listener,
  AuthenticatedChatConnection_preconnect,
  AuthenticatedChatConnection_send,
  AuthenticatedChatConnection_send_message,
  AuthenticatedChatConnection_send_raw_grpc,
  AuthenticatedChatConnection_send_sync_message,
  AuthenticatedChatConnection_set_device_name,
  AvatarUploadCredentialPresentation_CheckValidContents,
  AvatarUploadCredentialPresentation_GetCm,
  AvatarUploadCredentialPresentation_GetRedemptionTime,
  AvatarUploadCredentialPresentation_Verify,
  AvatarUploadCredentialRequestContext_CheckValidContents,
  AvatarUploadCredentialRequestContext_GetRequest,
  AvatarUploadCredentialRequestContext_New,
  AvatarUploadCredentialRequestContext_ReceiveResponse,
  AvatarUploadCredentialRequest_CheckValidContents,
  AvatarUploadCredentialRequest_IssueDeterministic,
  AvatarUploadCredentialResponse_CheckValidContents,
  AvatarUploadCredential_CheckValidContents,
  AvatarUploadCredential_GetCm,
  AvatarUploadCredential_GetRedemptionTime,
  AvatarUploadCredential_PresentDeterministic,
  BackupAuthCredentialPresentation_CheckValidContents,
  BackupAuthCredentialPresentation_GetBackupId,
  BackupAuthCredentialPresentation_GetBackupLevel,
  BackupAuthCredentialPresentation_GetType,
  BackupAuthCredentialPresentation_Verify,
  BackupAuthCredentialRequestContext_CheckValidContents,
  BackupAuthCredentialRequestContext_GetRequest,
  BackupAuthCredentialRequestContext_New,
  BackupAuthCredentialRequestContext_ReceiveResponse,
  BackupAuthCredentialRequest_CheckValidContents,
  BackupAuthCredentialRequest_IssueDeterministic,
  BackupAuthCredentialResponse_CheckValidContents,
  BackupAuthCredential_CheckValidContents,
  BackupAuthCredential_GetBackupId,
  BackupAuthCredential_GetBackupLevel,
  BackupAuthCredential_GetType,
  BackupAuthCredential_PresentDeterministic,
  BackupJsonExporter_ExportFrames,
  BackupJsonExporter_Finish,
  BackupJsonExporter_GetInitialChunk,
  BackupJsonExporter_New,
  BackupKey_DeriveBackupId,
  BackupKey_DeriveEcKey,
  BackupKey_DeriveLocalBackupMetadataKey,
  BackupKey_DeriveMediaEncryptionKey,
  BackupKey_DeriveMediaId,
  BackupKey_DeriveThumbnailTransitEncryptionKey,
  BackupRestoreResponse_GetForwardSecrecyToken,
  BackupRestoreResponse_GetNextBackupSecretData,
  BackupStoreResponse_GetForwardSecrecyToken,
  BackupStoreResponse_GetNextBackupSecretData,
  BackupStoreResponse_GetOpaqueMetadata,
  BridgedStringMap_insert,
  BridgedStringMap_new,
  CallLinkAuthCredentialPresentation_CheckValidContents,
  CallLinkAuthCredentialPresentation_GetUserId,
  CallLinkAuthCredentialPresentation_Verify,
  CallLinkAuthCredentialResponse_CheckValidContents,
  CallLinkAuthCredentialResponse_IssueDeterministic,
  CallLinkAuthCredentialResponse_Receive,
  CallLinkAuthCredential_CheckValidContents,
  CallLinkAuthCredential_PresentDeterministic,
  CallLinkPublicParams_CheckValidContents,
  CallLinkSecretParams_CheckValidContents,
  CallLinkSecretParams_DecryptUserId,
  CallLinkSecretParams_DeriveFromRootKey,
  CallLinkSecretParams_EncryptUserId,
  CallLinkSecretParams_GetPublicParams,
  Cds2ClientState_New,
  CdsiLookup_complete,
  CdsiLookup_new,
  CdsiLookup_token,
  ChatConnectionInfo_description,
  ChatConnectionInfo_ip_version,
  ChatConnectionInfo_local_port,
  CiphertextMessage_FromPlaintextContent,
  CiphertextMessage_Serialize,
  CiphertextMessage_Type,
  ComparableBackup_GetComparableString,
  ComparableBackup_GetUnknownFields,
  ComparableBackup_ReadUnencrypted,
  ConnectionManager_clear_proxy,
  ConnectionManager_new,
  ConnectionManager_on_network_change,
  ConnectionManager_set_censorship_circumvention_enabled,
  ConnectionManager_set_invalid_proxy,
  ConnectionManager_set_ipv6_enabled,
  ConnectionManager_set_proxy,
  ConnectionManager_set_remote_config,
  ConnectionProxyConfig_new,
  CreateCallLinkCredentialPresentation_CheckValidContents,
  CreateCallLinkCredentialPresentation_Verify,
  CreateCallLinkCredentialRequestContext_CheckValidContents,
  CreateCallLinkCredentialRequestContext_GetRequest,
  CreateCallLinkCredentialRequestContext_NewDeterministic,
  CreateCallLinkCredentialRequestContext_ReceiveResponse,
  CreateCallLinkCredentialRequest_CheckValidContents,
  CreateCallLinkCredentialRequest_IssueDeterministic,
  CreateCallLinkCredentialResponse_CheckValidContents,
  CreateCallLinkCredential_CheckValidContents,
  CreateCallLinkCredential_PresentDeterministic,
  DecryptionErrorMessage_Deserialize,
  DecryptionErrorMessage_ExtractFromSerializedContent,
  DecryptionErrorMessage_ForOriginalMessage,
  DecryptionErrorMessage_GetDeviceId,
  DecryptionErrorMessage_GetRatchetKey,
  DecryptionErrorMessage_GetTimestamp,
  DecryptionErrorMessage_Serialize,
  DonationPermitDerivedKeyPair_CheckValidContents,
  DonationPermitDerivedKeyPair_ForExpiration,
  DonationPermitRequestContext_CheckValidContents,
  DonationPermitRequestContext_NewDeterministic,
  DonationPermitRequestContext_Receive,
  DonationPermitRequestContext_Request,
  DonationPermitRequest_CheckValidContents,
  DonationPermitRequest_Len,
  DonationPermitResponse_CheckValidContents,
  DonationPermitResponse_DefaultExpiration,
  DonationPermitResponse_GetExpiration,
  DonationPermitResponse_IssueDeterministic,
  DonationPermit_CheckValidContents,
  DonationPermit_Expiration,
  DonationPermit_SpendId,
  DonationPermit_Verify,
  ExpiringProfileKeyCredentialResponse_CheckValidContents,
  ExpiringProfileKeyCredential_CheckValidContents,
  ExpiringProfileKeyCredential_GetExpirationTime,
  Fingerprint_DisplayString,
  Fingerprint_New,
  Fingerprint_ScannableEncoding,
  GenericServerPublicParams_CheckValidContents,
  GenericServerSecretParams_CheckValidContents,
  GenericServerSecretParams_GenerateDeterministic,
  GenericServerSecretParams_GetPublicParams,
  GroupCipher_DecryptMessage,
  GroupCipher_EncryptMessage,
  GroupMasterKey_CheckValidContents,
  GroupPublicParams_CheckValidContents,
  GroupPublicParams_GetGroupIdentifier,
  GroupSecretParams_CheckValidContents,
  GroupSecretParams_DecryptBlobWithPadding,
  GroupSecretParams_DecryptProfileKey,
  GroupSecretParams_DecryptServiceId,
  GroupSecretParams_DeriveFromMasterKey,
  GroupSecretParams_EncryptBlobWithPaddingDeterministic,
  GroupSecretParams_EncryptProfileKey,
  GroupSecretParams_EncryptServiceId,
  GroupSecretParams_GenerateDeterministic,
  GroupSecretParams_GetMasterKey,
  GroupSecretParams_GetPublicParams,
  GroupSendDerivedKeyPair_CheckValidContents,
  GroupSendDerivedKeyPair_ForExpiration,
  GroupSendEndorsement_CallLinkParams_ToToken,
  GroupSendEndorsement_CheckValidContents,
  GroupSendEndorsement_Combine,
  GroupSendEndorsement_Remove,
  GroupSendEndorsement_ToToken,
  GroupSendEndorsementsResponse_CheckValidContents,
  GroupSendEndorsementsResponse_GetExpiration,
  GroupSendEndorsementsResponse_IssueDeterministic,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts,
  GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds,
  GroupSendFullToken_CheckValidContents,
  GroupSendFullToken_GetExpiration,
  GroupSendFullToken_Verify,
  GroupSendToken_CheckValidContents,
  GroupSendToken_ToFullToken,
  HKDF_DeriveSecrets,
  HsmEnclaveClient_CompleteHandshake,
  HsmEnclaveClient_EstablishedRecv,
  HsmEnclaveClient_EstablishedSend,
  HsmEnclaveClient_InitialRequest,
  HsmEnclaveClient_New,
  HttpRequest_add_header,
  HttpRequest_new,
  IdentityKeyPair_Deserialize,
  IdentityKeyPair_Serialize,
  IdentityKeyPair_SignAlternateIdentity,
  IdentityKey_VerifyAlternateIdentity,
  IncrementalMac_CalculateChunkSize,
  IncrementalMac_Finalize,
  IncrementalMac_Initialize,
  IncrementalMac_Update,
  KeyTransparency_AciSearchKey,
  KeyTransparency_Check,
  KeyTransparency_E164SearchKey,
  KeyTransparency_ResetDataField,
  KeyTransparency_UsernameHashSearchKey,
  KyberKeyPair_Generate,
  KyberKeyPair_GetPublicKey,
  KyberKeyPair_GetSecretKey,
  KyberPreKeyRecord_Deserialize,
  KyberPreKeyRecord_GetId,
  KyberPreKeyRecord_GetKeyPair,
  KyberPreKeyRecord_GetPublicKey,
  KyberPreKeyRecord_GetSecretKey,
  KyberPreKeyRecord_GetSignature,
  KyberPreKeyRecord_GetTimestamp,
  KyberPreKeyRecord_New,
  KyberPreKeyRecord_Serialize,
  KyberPublicKey_Deserialize,
  KyberPublicKey_Equals,
  KyberPublicKey_Serialize,
  KyberSecretKey_Deserialize,
  KyberSecretKey_Serialize,
  LookupRequest_addAciAndAccessKey,
  LookupRequest_addE164,
  LookupRequest_addPreviousE164,
  LookupRequest_new,
  LookupRequest_setToken,
  MessageBackupKey_FromAccountEntropyPool,
  MessageBackupKey_FromBackupKeyAndBackupId,
  MessageBackupKey_GetAesKey,
  MessageBackupKey_GetHmacKey,
  MessageBackupValidator_Validate,
  MinidumpToJSONString,
  Mp4Sanitizer_Sanitize,
  OnlineBackupValidator_AddFrame,
  OnlineBackupValidator_Finalize,
  OnlineBackupValidator_New,
  PinHash_AccessKey,
  PinHash_EncryptionKey,
  PinHash_FromSalt,
  PinHash_FromUsernameMrenclave,
  Pin_LocalHash,
  Pin_VerifyLocalHash,
  PlaintextContent_Deserialize,
  PlaintextContent_FromDecryptionErrorMessage,
  PlaintextContent_GetBody,
  PlaintextContent_Serialize,
  PreKeyBundle_GetDeviceId,
  PreKeyBundle_GetIdentityKey,
  PreKeyBundle_GetKyberPreKeyId,
  PreKeyBundle_GetKyberPreKeyPublic,
  PreKeyBundle_GetKyberPreKeySignature,
  PreKeyBundle_GetPreKeyId,
  PreKeyBundle_GetPreKeyPublic,
  PreKeyBundle_GetRegistrationId,
  PreKeyBundle_GetSignedPreKeyId,
  PreKeyBundle_GetSignedPreKeyPublic,
  PreKeyBundle_GetSignedPreKeySignature,
  PreKeyBundle_New,
  PreKeyRecord_Deserialize,
  PreKeyRecord_GetId,
  PreKeyRecord_GetPrivateKey,
  PreKeyRecord_GetPublicKey,
  PreKeyRecord_New,
  PreKeyRecord_Serialize,
  PreKeySignalMessage_Deserialize,
  PreKeySignalMessage_GetPreKeyId,
  PreKeySignalMessage_GetRegistrationId,
  PreKeySignalMessage_GetSignedPreKeyId,
  PreKeySignalMessage_GetVersion,
  PreKeySignalMessage_New,
  PreKeySignalMessage_Serialize,
  PrivateKey_Agree,
  PrivateKey_Deserialize,
  PrivateKey_Generate,
  PrivateKey_GetPublicKey,
  PrivateKey_HpkeOpen,
  PrivateKey_Serialize,
  PrivateKey_Sign,
  ProfileKeyCiphertext_CheckValidContents,
  ProfileKeyCommitment_CheckValidContents,
  ProfileKeyCredentialPresentation_CheckValidContents,
  ProfileKeyCredentialPresentation_GetProfileKeyCiphertext,
  ProfileKeyCredentialPresentation_GetUuidCiphertext,
  ProfileKeyCredentialRequestContext_CheckValidContents,
  ProfileKeyCredentialRequestContext_GetRequest,
  ProfileKeyCredentialRequest_CheckValidContents,
  ProfileKey_CheckValidContents,
  ProfileKey_DeriveAccessKey,
  ProfileKey_GetCommitment,
  ProfileKey_GetProfileKeyVersion,
  ProtocolAddress_DeviceId,
  ProtocolAddress_Name,
  ProtocolAddress_New,
  ProvisioningChatConnection_connect,
  ProvisioningChatConnection_disconnect,
  ProvisioningChatConnection_info,
  ProvisioningChatConnection_init_listener,
  PublicKey_Deserialize,
  PublicKey_Equals,
  PublicKey_GetPublicKeyBytes,
  PublicKey_HpkeSeal,
  PublicKey_Serialize,
  PublicKey_Verify,
  ReceiptCredentialPresentation_CheckValidContents,
  ReceiptCredentialPresentation_GetReceiptExpirationTime,
  ReceiptCredentialPresentation_GetReceiptLevel,
  ReceiptCredentialPresentation_GetReceiptSerial,
  ReceiptCredentialRequestContext_CheckValidContents,
  ReceiptCredentialRequestContext_GetRequest,
  ReceiptCredentialRequest_CheckValidContents,
  ReceiptCredentialResponse_CheckValidContents,
  ReceiptCredential_CheckValidContents,
  ReceiptCredential_GetReceiptExpirationTime,
  ReceiptCredential_GetReceiptLevel,
  RegisterAccountRequest_Create,
  RegisterAccountRequest_SetAccountPassword,
  RegisterAccountRequest_SetIdentityPqLastResortPreKey,
  RegisterAccountRequest_SetIdentityPublicKey,
  RegisterAccountRequest_SetIdentitySignedPreKey,
  RegisterAccountRequest_SetSkipDeviceTransfer,
  RegisterAccountResponse_GetEntitlementBackupExpirationSeconds,
  RegisterAccountResponse_GetEntitlementBackupLevel,
  RegisterAccountResponse_GetEntitlementBadges,
  RegisterAccountResponse_GetIdentity,
  RegisterAccountResponse_GetNumber,
  RegisterAccountResponse_GetReregistration,
  RegisterAccountResponse_GetStorageCapable,
  RegisterAccountResponse_GetUsernameHash,
  RegisterAccountResponse_GetUsernameLinkHandle,
  RegistrationAccountAttributes_Create,
  RegistrationService_CheckSvr2Credentials,
  RegistrationService_CreateSession,
  RegistrationService_RegisterAccount,
  RegistrationService_RegistrationSession,
  RegistrationService_RequestVerificationCode,
  RegistrationService_ReregisterAccount,
  RegistrationService_ResumeSession,
  RegistrationService_SessionId,
  RegistrationService_SubmitCaptcha,
  RegistrationService_SubmitVerificationCode,
  RegistrationSession_GetAllowedToRequestCode,
  RegistrationSession_GetNextCallSeconds,
  RegistrationSession_GetNextSmsSeconds,
  RegistrationSession_GetNextVerificationAttemptSeconds,
  RegistrationSession_GetRequestedInformation,
  RegistrationSession_GetVerified,
  SanitizedMetadata_GetDataLen,
  SanitizedMetadata_GetDataOffset,
  SanitizedMetadata_GetMetadata,
  ScannableFingerprint_Compare,
  SealedSenderDecryptionResult_GetDeviceId,
  SealedSenderDecryptionResult_GetSenderE164,
  SealedSenderDecryptionResult_GetSenderUuid,
  SealedSenderDecryptionResult_Message,
  SealedSenderMultiRecipientMessage_Parse,
  SealedSender_DecryptMessage,
  SealedSender_DecryptToUsmc,
  SealedSender_Encrypt,
  SealedSender_MultiRecipientEncrypt,
  SealedSender_MultiRecipientMessageForSingleRecipient,
  SecureValueRecoveryForBackups_CreateNewBackupChain,
  SecureValueRecoveryForBackups_RemoveBackup,
  SecureValueRecoveryForBackups_RestoreBackupFromServer,
  SecureValueRecoveryForBackups_StoreBackup,
  SenderCertificate_Deserialize,
  SenderCertificate_GetCertificate,
  SenderCertificate_GetDeviceId,
  SenderCertificate_GetExpiration,
  SenderCertificate_GetKey,
  SenderCertificate_GetSenderE164,
  SenderCertificate_GetSenderUuid,
  SenderCertificate_GetSerialized,
  SenderCertificate_GetServerCertificate,
  SenderCertificate_GetSignature,
  SenderCertificate_New,
  SenderCertificate_Validate,
  SenderKeyDistributionMessage_Create,
  SenderKeyDistributionMessage_Deserialize,
  SenderKeyDistributionMessage_GetChainId,
  SenderKeyDistributionMessage_GetChainKey,
  SenderKeyDistributionMessage_GetDistributionId,
  SenderKeyDistributionMessage_GetIteration,
  SenderKeyDistributionMessage_New,
  SenderKeyDistributionMessage_Process,
  SenderKeyDistributionMessage_Serialize,
  SenderKeyMessage_Deserialize,
  SenderKeyMessage_GetChainId,
  SenderKeyMessage_GetCipherText,
  SenderKeyMessage_GetDistributionId,
  SenderKeyMessage_GetIteration,
  SenderKeyMessage_New,
  SenderKeyMessage_Serialize,
  SenderKeyMessage_VerifySignature,
  SenderKeyRecord_Deserialize,
  SenderKeyRecord_Serialize,
  ServerCertificate_Deserialize,
  ServerCertificate_GetCertificate,
  ServerCertificate_GetKey,
  ServerCertificate_GetKeyId,
  ServerCertificate_GetSerialized,
  ServerCertificate_GetSignature,
  ServerCertificate_New,
  ServerMessageAck_SendStatus,
  ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic,
  ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic,
  ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic,
  ServerPublicParams_CreateReceiptCredentialPresentationDeterministic,
  ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic,
  ServerPublicParams_Deserialize,
  ServerPublicParams_GetEndorsementPublicKey,
  ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId,
  ServerPublicParams_ReceiveExpiringProfileKeyCredential,
  ServerPublicParams_ReceiveReceiptCredential,
  ServerPublicParams_Serialize,
  ServerPublicParams_VerifySignature,
  ServerSecretParams_Deserialize,
  ServerSecretParams_GenerateDeterministic,
  ServerSecretParams_GetPublicParams,
  ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic,
  ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic,
  ServerSecretParams_IssueReceiptCredentialDeterministic,
  ServerSecretParams_Serialize,
  ServerSecretParams_SignDeterministic,
  ServerSecretParams_VerifyAuthCredentialPresentation,
  ServerSecretParams_VerifyProfileKeyCredentialPresentation,
  ServerSecretParams_VerifyReceiptCredentialPresentation,
  ServiceId_ParseFromServiceIdBinary,
  ServiceId_ParseFromServiceIdString,
  ServiceId_ServiceIdBinary,
  ServiceId_ServiceIdLog,
  ServiceId_ServiceIdString,
  SessionBuilder_ProcessPreKeyBundle,
  SessionCipher_DecryptPreKeySignalMessage,
  SessionCipher_DecryptSignalMessage,
  SessionCipher_EncryptMessage,
  SessionRecord_ArchiveCurrentState,
  SessionRecord_CurrentRatchetKeyMatches,
  SessionRecord_Deserialize,
  SessionRecord_GetLocalRegistrationId,
  SessionRecord_GetRemoteRegistrationId,
  SessionRecord_HasUsableSenderChain,
  SessionRecord_Serialize,
  SgxClientState_CompleteHandshake,
  SgxClientState_EstablishedRecv,
  SgxClientState_EstablishedSend,
  SgxClientState_InitialRequest,
  SignalMedia_CheckAvailable,
  SignalMessage_Deserialize,
  SignalMessage_GetBody,
  SignalMessage_GetCounter,
  SignalMessage_GetMessageVersion,
  SignalMessage_GetPqRatchet,
  SignalMessage_GetSerialized,
  SignalMessage_New,
  SignedPreKeyRecord_Deserialize,
  SignedPreKeyRecord_GetId,
  SignedPreKeyRecord_GetPrivateKey,
  SignedPreKeyRecord_GetPublicKey,
  SignedPreKeyRecord_GetSignature,
  SignedPreKeyRecord_GetTimestamp,
  SignedPreKeyRecord_New,
  SignedPreKeyRecord_Serialize,
  Svr2Client_New,
  Svr2_Delete,
  Svr2_FinishBackup,
  Svr2_Restore,
  Svr2_StartBackup,
  TESTING_BridgedStringMap_dump_to_json,
  TESTING_CdsiLookupErrorConvert,
  TESTING_CdsiLookupResponseConvert,
  TESTING_ChatConnectErrorConvert,
  TESTING_ChatRequestGetBody,
  TESTING_ChatRequestGetHeaderNames,
  TESTING_ChatRequestGetHeaderValue,
  TESTING_ChatRequestGetMethod,
  TESTING_ChatRequestGetPath,
  TESTING_ChatResponseConvert,
  TESTING_ChatSendErrorConvert,
  TESTING_ConnectionManager_isUsingProxy,
  TESTING_ConnectionManager_newLocalOverride,
  TESTING_ConvertOptionalUuid,
  TESTING_CreateOTP,
  TESTING_CreateOTPFromBase64,
  TESTING_EnableDeterministicRngForTesting,
  TESTING_ErrorOnBorrowAsync,
  TESTING_ErrorOnBorrowIo,
  TESTING_ErrorOnBorrowSync,
  TESTING_ErrorOnReturnAsync,
  TESTING_ErrorOnReturnIo,
  TESTING_ErrorOnReturnSync,
  TESTING_FakeChatConnection_Create,
  TESTING_FakeChatConnection_CreateProvisioning,
  TESTING_FakeChatConnection_TakeAuthenticatedChat,
  TESTING_FakeChatConnection_TakeProvisioningChat,
  TESTING_FakeChatConnection_TakeRemote,
  TESTING_FakeChatConnection_TakeUnauthenticatedChat,
  TESTING_FakeChatRemoteEnd_BinprotoToJson,
  TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength,
  TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted,
  TESTING_FakeChatRemoteEnd_JsonToBinproto,
  TESTING_FakeChatRemoteEnd_NextGrpcMessage,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest,
  TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerRequest,
  TESTING_FakeChatRemoteEnd_SendRawServerResponse,
  TESTING_FakeChatRemoteEnd_SendServerGrpcResponse,
  TESTING_FakeChatRemoteEnd_SendServerResponse,
  TESTING_FakeChatResponse_Create,
  TESTING_FakeChatServer_Create,
  TESTING_FakeChatServer_GetNextRemote,
  TESTING_FakeRegistrationSession_CreateSession,
  TESTING_FutureCancellationCounter_Create,
  TESTING_FutureCancellationCounter_WaitForCount,
  TESTING_FutureFailure,
  TESTING_FutureIncrementOnCancel,
  TESTING_FutureProducesOtherPointerType,
  TESTING_FutureProducesPointerType,
  TESTING_FutureSuccess,
  TESTING_InputStreamReadIntoZeroLengthSlice,
  TESTING_JoinStringArray,
  TESTING_KeyTransChatSendError,
  TESTING_KeyTransFatalVerificationFailure,
  TESTING_KeyTransNonFatalVerificationFailure,
  TESTING_KeyTransStoredAccountData,
  TESTING_MyRemoteDeriveEnum_identity,
  TESTING_MyRemoteDeriveStruct_identity,
  TESTING_MySimpleTestEnum_identity,
  TESTING_MySimpleTestEnum_identity_async,
  TESTING_MySimpleTestEnum_to_string,
  TESTING_MyTestEnum_identity,
  TESTING_MyTestEnum_identity_async,
  TESTING_MyTestEnum_to_string,
  TESTING_MyTestPoint_identity,
  TESTING_MyTestPoint_identity_async,
  TESTING_MyTestPoint_to_string,
  TESTING_MyTestStruct_identity,
  TESTING_MyTestStruct_identity_async,
  TESTING_MyTestStruct_to_string,
  TESTING_NonSuspendingBackgroundThreadRuntime_New,
  TESTING_OtherTestingHandleType_getValue,
  TESTING_PanicInBodyAsync,
  TESTING_PanicInBodyIo,
  TESTING_PanicInBodySync,
  TESTING_PanicOnBorrowAsync,
  TESTING_PanicOnBorrowIo,
  TESTING_PanicOnBorrowSync,
  TESTING_PanicOnLoadAsync,
  TESTING_PanicOnLoadIo,
  TESTING_PanicOnLoadSync,
  TESTING_PanicOnReturnAsync,
  TESTING_PanicOnReturnIo,
  TESTING_PanicOnReturnSync,
  TESTING_ProcessBytestringArray,
  TESTING_RegisterAccountResponse_CreateTestValue,
  TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert,
  TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert,
  TESTING_RegistrationService_CreateSessionErrorConvert,
  TESTING_RegistrationService_RegisterAccountErrorConvert,
  TESTING_RegistrationService_RequestVerificationCodeErrorConvert,
  TESTING_RegistrationService_ResumeSessionErrorConvert,
  TESTING_RegistrationService_SubmitVerificationErrorConvert,
  TESTING_RegistrationService_UpdateSessionErrorConvert,
  TESTING_RegistrationSessionInfoConvert,
  TESTING_ReturnPair,
  TESTING_ReturnStringArray,
  TESTING_RoundTripI32,
  TESTING_RoundTripU16,
  TESTING_RoundTripU32,
  TESTING_RoundTripU64,
  TESTING_RoundTripU8,
  TESTING_ServerMessageAck_Create,
  TESTING_SetDeviceNameTests,
  TESTING_SignedPublicPreKey_CheckBridgesCorrectly,
  TESTING_TestingHandleType_getValue,
  TESTING_TestingIntBox_Get,
  TESTING_TestingIntBox_New,
  TESTING_TokioAsyncContext_FutureSuccessBytes,
  TESTING_TokioAsyncContext_NewSingleThreaded,
  TESTING_TokioAsyncFuture,
  TESTING_conversion_Data_VecU8_identity,
  TESTING_conversion_Data_VecU8_identity_async,
  TESTING_conversion_Data_VecU8_to_string,
  TESTING_conversion_Data_identity,
  TESTING_conversion_Data_identity_async,
  TESTING_conversion_Data_to_string,
  TESTING_conversion_ServiceId_identity,
  TESTING_conversion_ServiceId_identity_async,
  TESTING_conversion_ServiceId_to_string,
  TESTING_conversion_bool_identity,
  TESTING_conversion_bool_identity_async,
  TESTING_conversion_bool_to_string,
  TESTING_conversion_i32_identity,
  TESTING_conversion_i32_identity_async,
  TESTING_conversion_i32_to_string,
  TESTING_conversion_string_identity,
  TESTING_conversion_string_identity_async,
  TESTING_conversion_u16_identity,
  TESTING_conversion_u16_identity_async,
  TESTING_conversion_u16_to_string,
  TESTING_conversion_u8_identity,
  TESTING_conversion_u8_identity_async,
  TESTING_conversion_u8_to_string,
  TestingSemaphore_AddPermits,
  TestingSemaphore_New,
  TestingValueHolder_Get,
  TestingValueHolder_New,
  TokioAsyncContext_cancel,
  TokioAsyncContext_new,
  UnauthenticatedChatConnection_account_exists,
  UnauthenticatedChatConnection_backup_delete_all,
  UnauthenticatedChatConnection_backup_get_cdn_credentials,
  UnauthenticatedChatConnection_backup_get_media_upload_form,
  UnauthenticatedChatConnection_backup_get_svrb_credentials,
  UnauthenticatedChatConnection_backup_get_upload_form,
  UnauthenticatedChatConnection_backup_refresh,
  UnauthenticatedChatConnection_backup_set_public_key,
  UnauthenticatedChatConnection_connect,
  UnauthenticatedChatConnection_disconnect,
  UnauthenticatedChatConnection_get_pre_keys_access_key_auth,
  UnauthenticatedChatConnection_get_pre_keys_group_auth,
  UnauthenticatedChatConnection_get_pre_keys_unrestricted_auth,
  UnauthenticatedChatConnection_info,
  UnauthenticatedChatConnection_init_listener,
  UnauthenticatedChatConnection_look_up_username_hash,
  UnauthenticatedChatConnection_look_up_username_link,
  UnauthenticatedChatConnection_send,
  UnauthenticatedChatConnection_send_message,
  UnauthenticatedChatConnection_send_multi_recipient_message,
  UnauthenticatedChatConnection_send_raw_grpc,
  UnidentifiedSenderMessageContent_Deserialize,
  UnidentifiedSenderMessageContent_GetContentHint,
  UnidentifiedSenderMessageContent_GetContents,
  UnidentifiedSenderMessageContent_GetGroupId,
  UnidentifiedSenderMessageContent_GetMsgType,
  UnidentifiedSenderMessageContent_GetSenderCert,
  UnidentifiedSenderMessageContent_New,
  UnidentifiedSenderMessageContent_Serialize,
  UsernameLink_Create,
  UsernameLink_DecryptUsername,
  Username_CandidatesFrom,
  Username_Hash,
  Username_HashFromParts,
  Username_Proof,
  Username_Verify,
  UuidCiphertext_CheckValidContents,
  ValidatingMac_Finalize,
  ValidatingMac_Initialize,
  ValidatingMac_Update,
  WebpSanitizer_Sanitize,
  ZkCredentialKeyPair_CheckValidContents,
  ZkCredentialKeyPair_GenerateDeterministic,
  ZkCredentialKeyPair_GetPublicKey,
  ZkCredentialPublicKey_CheckValidContents,
  test_only_fn_returns_123,
  uuid_from_string,
  uuid_new_v4,
  uuid_to_string,
};

export /*trait*/ type ChatListener = {
  receivedIncomingMessage: (
    envelope: Uint8Array<ArrayBuffer>,
    timestamp: Timestamp,
    ack: ServerMessageAck
  ) => void;
  receivedQueueEmpty: () => void;
  receivedAlerts: (alerts: Array<string>) => void;
  connectionInterrupted: (disconnectCause: Error | null) => void;
};

export /*trait*/ type IdentityKeyStore = {
  getLocalIdentityKeyPair: () => Promise<[PrivateKey, PublicKey]>;
  getLocalRegistrationId: () => Promise<number>;
  getIdentityKey: (address: ProtocolAddress) => Promise<PublicKey | null>;
  saveIdentityKey: (
    address: ProtocolAddress,
    publicKey: PublicKey
  ) => Promise<number>;
  isTrustedIdentity: (
    address: ProtocolAddress,
    publicKey: PublicKey,
    direction: number
  ) => Promise<boolean>;
};

export /*trait*/ type InputStream = {
  read: (amount: number) => Promise<Uint8Array<ArrayBuffer>>;
  skip: (amount: bigint) => Promise<void>;
};

export /*trait*/ type KyberPreKeyStore = {
  loadKyberPreKey: (id: number) => Promise<KyberPreKeyRecord | null>;
  storeKyberPreKey: (id: number, record: KyberPreKeyRecord) => Promise<void>;
  markKyberPreKeyUsed: (
    id: number,
    ecPrekeyId: number,
    baseKey: PublicKey
  ) => Promise<void>;
};

export /*trait*/ type PreKeyStore = {
  loadPreKey: (id: number) => Promise<PreKeyRecord | null>;
  storePreKey: (id: number, record: PreKeyRecord) => Promise<void>;
  removePreKey: (id: number) => Promise<void>;
};

export /*trait*/ type ProvisioningListener = {
  receivedAddress: (address: string, sendAck: ServerMessageAck) => void;
  receivedEnvelope: (
    envelope: Uint8Array<ArrayBuffer>,
    sendAck: ServerMessageAck
  ) => void;
  connectionInterrupted: (disconnectCause: Error | null) => void;
};

export /*trait*/ type SenderKeyStore = {
  loadSenderKey: (
    sender: ProtocolAddress,
    distributionId: Uuid
  ) => Promise<SenderKeyRecord | null>;
  storeSenderKey: (
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord
  ) => Promise<void>;
};

export /*trait*/ type SessionStore = {
  loadSession: (address: ProtocolAddress) => Promise<SessionRecord | null>;
  storeSession: (
    address: ProtocolAddress,
    record: SessionRecord
  ) => Promise<void>;
};

export /*trait*/ type SignedPreKeyStore = {
  loadSignedPreKey: (id: number) => Promise<SignedPreKeyRecord | null>;
  storeSignedPreKey: (id: number, record: SignedPreKeyRecord) => Promise<void>;
};

export interface Aes256GcmSiv {
  readonly __type: unique symbol;
}
export interface AuthenticatedChatConnection {
  readonly __type: unique symbol;
}
export interface BackupJsonExporter {
  readonly __type: unique symbol;
}
export interface BackupRestoreResponse {
  readonly __type: unique symbol;
}
export interface BackupStoreResponse {
  readonly __type: unique symbol;
}
export interface BridgedStringMap {
  readonly __type: unique symbol;
}
export interface CdsiLookup {
  readonly __type: unique symbol;
}
export interface ChatConnectionInfo {
  readonly __type: unique symbol;
}
export interface CiphertextMessage {
  readonly __type: unique symbol;
}
export interface ComparableBackup {
  readonly __type: unique symbol;
}
export interface ConnectionManager {
  readonly __type: unique symbol;
}
export interface ConnectionProxyConfig {
  readonly __type: unique symbol;
}
export interface DecryptionErrorMessage {
  readonly __type: unique symbol;
}
export interface ExpiringProfileKeyCredential {
  readonly __type: unique symbol;
}
export interface ExpiringProfileKeyCredentialResponse {
  readonly __type: unique symbol;
}
export interface FakeChatConnection {
  readonly __type: unique symbol;
}
export interface FakeChatRemoteEnd {
  readonly __type: unique symbol;
}
export interface FakeChatResponse {
  readonly __type: unique symbol;
}
export interface FakeChatServer {
  readonly __type: unique symbol;
}
export interface Fingerprint {
  readonly __type: unique symbol;
}
export interface GroupMasterKey {
  readonly __type: unique symbol;
}
export interface GroupPublicParams {
  readonly __type: unique symbol;
}
export interface GroupSecretParams {
  readonly __type: unique symbol;
}
export interface HsmEnclaveClient {
  readonly __type: unique symbol;
}
export interface HttpRequest {
  readonly __type: unique symbol;
}
export interface IncrementalMac {
  readonly __type: unique symbol;
}
export interface KyberKeyPair {
  readonly __type: unique symbol;
}
export interface KyberPreKeyRecord {
  readonly __type: unique symbol;
}
export interface KyberPublicKey {
  readonly __type: unique symbol;
}
export interface KyberSecretKey {
  readonly __type: unique symbol;
}
export interface LookupRequest {
  readonly __type: unique symbol;
}
export interface MessageBackupKey {
  readonly __type: unique symbol;
}
export interface NonSuspendingBackgroundThreadRuntime {
  readonly __type: unique symbol;
}
export interface OnlineBackupValidator {
  readonly __type: unique symbol;
}
export interface OtherTestingHandleType {
  readonly __type: unique symbol;
}
export interface PinHash {
  readonly __type: unique symbol;
}
export interface PlaintextContent {
  readonly __type: unique symbol;
}
export interface PreKeyBundle {
  readonly __type: unique symbol;
}
export interface PreKeyRecord {
  readonly __type: unique symbol;
}
export interface PreKeySignalMessage {
  readonly __type: unique symbol;
}
export interface PrivateKey {
  readonly __type: unique symbol;
}
export interface ProfileKey {
  readonly __type: unique symbol;
}
export interface ProfileKeyCiphertext {
  readonly __type: unique symbol;
}
export interface ProfileKeyCommitment {
  readonly __type: unique symbol;
}
export interface ProfileKeyCredentialRequest {
  readonly __type: unique symbol;
}
export interface ProfileKeyCredentialRequestContext {
  readonly __type: unique symbol;
}
export interface ProtocolAddress {
  readonly __type: unique symbol;
}
export interface ProvisioningChatConnection {
  readonly __type: unique symbol;
}
export interface PublicKey {
  readonly __type: unique symbol;
}
export interface ReceiptCredential {
  readonly __type: unique symbol;
}
export interface ReceiptCredentialPresentation {
  readonly __type: unique symbol;
}
export interface ReceiptCredentialRequest {
  readonly __type: unique symbol;
}
export interface ReceiptCredentialRequestContext {
  readonly __type: unique symbol;
}
export interface ReceiptCredentialResponse {
  readonly __type: unique symbol;
}
export interface RegisterAccountRequest {
  readonly __type: unique symbol;
}
export interface RegisterAccountResponse {
  readonly __type: unique symbol;
}
export interface RegistrationAccountAttributes {
  readonly __type: unique symbol;
}
export interface RegistrationService {
  readonly __type: unique symbol;
}
export interface RegistrationSession {
  readonly __type: unique symbol;
}
export interface SanitizedMetadata {
  readonly __type: unique symbol;
}
export interface SealedSenderDecryptionResult {
  readonly __type: unique symbol;
}
export interface SenderCertificate {
  readonly __type: unique symbol;
}
export interface SenderKeyDistributionMessage {
  readonly __type: unique symbol;
}
export interface SenderKeyMessage {
  readonly __type: unique symbol;
}
export interface SenderKeyRecord {
  readonly __type: unique symbol;
}
export interface ServerCertificate {
  readonly __type: unique symbol;
}
export interface ServerMessageAck {
  readonly __type: unique symbol;
}
export interface ServerPublicParams {
  readonly __type: unique symbol;
}
export interface ServerSecretParams {
  readonly __type: unique symbol;
}
export interface SessionRecord {
  readonly __type: unique symbol;
}
export interface SgxClientState {
  readonly __type: unique symbol;
}
export interface SignalMessage {
  readonly __type: unique symbol;
}
export interface SignedPreKeyRecord {
  readonly __type: unique symbol;
}
export interface Svr2BackupSession {
  readonly __type: unique symbol;
}
export interface TestingFutureCancellationCounter {
  readonly __type: unique symbol;
}
export interface TestingHandleType {
  readonly __type: unique symbol;
}
export interface TestingIntBox {
  readonly __type: unique symbol;
}
export interface TestingSemaphore {
  readonly __type: unique symbol;
}
export interface TestingValueHolder {
  readonly __type: unique symbol;
}
export interface TokioAsyncContext {
  readonly __type: unique symbol;
}
export interface UnauthenticatedChatConnection {
  readonly __type: unique symbol;
}
export interface UnidentifiedSenderMessageContent {
  readonly __type: unique symbol;
}
export interface UuidCiphertext {
  readonly __type: unique symbol;
}
export interface ValidatingMac {
  readonly __type: unique symbol;
}
