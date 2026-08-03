//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

import * as Native from './Native.js';
import type {
  /* eslint-disable @typescript-eslint/no-unused-vars */
  GrpcTestCase,
  ArgFfiBridgeCopyBackupMediaItem,
  ArgFfiBridgeDeleteBackupMediaItem,
  ArgFfiMyRemoteDeriveEnum,
  ArgFfiMyRemoteDeriveStruct,
  ArgFfiMySimpleTestEnum,
  ArgFfiMyTestEnum,
  ArgFfiMyTestPoint,
  ArgFfiMyTestStruct,
  ReturnFfiBridgeCopyBackupMediaItem,
  ReturnFfiBridgeCopyBackupMediaOutcome,
  ReturnFfiBridgeCopyBackupMediaResult,
  ReturnFfiBridgeDeleteBackupMediaItem,
  ReturnFfiBridgeMediaBackupInfo,
  ReturnFfiBridgeMessageBackupInfo,
  ReturnFfiCopyBackupMediaNextChunk,
  ReturnFfiCopyBackupMediaOut,
  ReturnFfiDeleteBackupMediaNextChunk,
  ReturnFfiDeleteBackupMediaOut,
  ReturnFfiGetDevicesOut,
  ReturnFfiGetMediaBackupInfoOut,
  ReturnFfiGetMessageBackupInfoOut,
  ReturnFfiLinkedDeviceInternal,
  ReturnFfiMyRemoteDeriveEnum,
  ReturnFfiMyRemoteDeriveStruct,
  ReturnFfiMySimpleTestEnum,
  ReturnFfiMyTestEnum,
  ReturnFfiMyTestPoint,
  ReturnFfiMyTestStruct,
  ReturnFfiRemoveDeviceArgs,
  ReturnFfiRemoveDeviceOut,
  ReturnFfiReserveUsernameHashArgs,
  ReturnFfiReserveUsernameHashOut,
  ReturnFfiSetDeviceNameArgs,
  ReturnFfiSetDeviceNameOut,
  ReturnFfiSetUsernameLinkArgs,
  ReturnFfiSetUsernameLinkOut,
  ReturnFfiTestStreamChunk,
  /* eslint-enable @typescript-eslint/no-unused-vars */
} from './Native.js';

import { ServiceId } from './Address.js';
import * as zkgroup from './zkgroup/index.js';
import * as uuid from './uuid.js';
import ByteArray from './zkgroup/internal/ByteArray.js';
import type { TokioAsyncContext } from './net.js';
import type { CdnCredentials } from './net/chat/CdnCredentials.js';
import {
  DeviceId,
  Timestamp,
  cdnCredentialReturnConverter,
  copyBackupMediaStreamConverter,
  deleteBackupMediaStreamConverter,
  identity,
  serviceIdArgConverter,
  grpcTestCaseConverter,
} from './NiceConverters.js';
import { Rng } from './RngForTesting.js';

export type BridgeCopyBackupMediaItem = {
  sourceAttachmentCdn: number;
  sourceKey: string;
  objectLength: bigint;
  mediaId: Uint8Array<ArrayBuffer>;
  encryptionKey: Uint8Array<ArrayBuffer>;
};

export type BridgeCopyBackupMediaOutcome = {
  mediaId: Uint8Array<ArrayBuffer>;
  result: BridgeCopyBackupMediaResult;
};

export type BridgeCopyBackupMediaResult =
  | {
      success: number;
    }
  | 'sourceNotFound'
  | 'wrongSourceLength'
  | 'outOfSpace';

export type BridgeDeleteBackupMediaItem = {
  mediaId: Uint8Array<ArrayBuffer>;
  cdn: number;
};

export type BridgeMediaBackupInfo = {
  backupDir: string;
  mediaDir: string;
  usedSpace: bigint;
};

export type BridgeMessageBackupInfo = {
  backupDir: string;
  cdn: number;
  backupName: string;
};

export type CopyBackupMediaNextChunk = {
  chunk: Array<BridgeCopyBackupMediaOutcome>;
  termination: ('finished' | Error) | null;
};

export type CopyBackupMediaOut =
  | {
      item: BridgeCopyBackupMediaOutcome;
    }
  | 'invalidDataInStream'
  | 'credentialRejected'
  | 'credentialRejectedWithoutAppropriateServerInfo';

export type DeleteBackupMediaNextChunk = {
  chunk: Array<BridgeDeleteBackupMediaItem>;
  termination: ('finished' | Error) | null;
};

export type DeleteBackupMediaOut =
  | {
      item: BridgeDeleteBackupMediaItem;
    }
  | 'invalidDataInStream'
  | 'credentialRejected'
  | 'credentialRejectedWithoutAppropriateServerInfo';

export type GetDevicesOut = {
  devices: Array<LinkedDeviceInternal>;
};

export type GetMediaBackupInfoOut =
  | {
      success: BridgeMediaBackupInfo;
    }
  | 'credentialRejected'
  | 'missingResponse';

export type GetMessageBackupInfoOut =
  | {
      success: BridgeMessageBackupInfo;
    }
  | 'credentialRejected'
  | 'missingResponse';

export type LinkedDeviceInternal = {
  id: DeviceId;
  encryptedName: Uint8Array<ArrayBuffer>;
  lastSeen: Timestamp;
  registrationId: number;
  createdAtCiphertext: Uint8Array<ArrayBuffer>;
};

export type MyRemoteDeriveEnum =
  | 'unit'
  | {
      tuple: [number, number];
    }
  | {
      record: {
        x: string;
        y: number;
      };
    };

export type MyRemoteDeriveStruct = {
  x: number;
  y: number;
};

export type MySimpleTestEnum = 'a' | 'b';

export type MyTestEnum =
  | 'unit'
  | {
      single: number;
    }
  | {
      singleNamed: number;
    }
  | {
      double: [number, number];
    }
  | {
      record: {
        personName: string;
        personAge: number;
        position: MyTestPoint;
        funStruct: MyTestStruct;
      };
    };

export type MyTestPoint = [number, number];

export type MyTestStruct = {
  myNumericField: number;
  myStringField: string;
};

export type RemoveDeviceArgs = {
  id: number;
};

export type RemoveDeviceOut = 'success';

export type ReserveUsernameHashArgs = {
  usernames: Array<Uint8Array<ArrayBuffer>>;
};

export type ReserveUsernameHashOut =
  | {
      success: Uint8Array<ArrayBuffer>;
    }
  | 'usernameNotAvailable';

export type SetDeviceNameArgs = {
  id: number;
  encryptedName: Uint8Array<ArrayBuffer>;
};

export type SetDeviceNameOut = 'success' | 'deviceNotFound';

export type SetUsernameLinkArgs = {
  usernameCiphertext: Uint8Array<ArrayBuffer>;
  keepLinkHandle: boolean;
};

export type SetUsernameLinkOut =
  | {
      success: uuid.Uuid;
    }
  | 'usernameNotSet';

export type TestStreamChunk = {
  chunk: Array<string>;
  termination: ('finished' | Error) | null;
};

export function returnConverterBridgeCopyBackupMediaItem(
  ffiInput: Native.ReturnFfiBridgeCopyBackupMediaItem
): BridgeCopyBackupMediaItem {
  return {
    sourceAttachmentCdn: identity(ffiInput.source_attachment_cdn),
    sourceKey: identity(ffiInput.source_key),
    objectLength: identity(ffiInput.object_length),
    mediaId: identity(ffiInput.media_id),
    encryptionKey: identity(ffiInput.encryption_key),
  };
}

export function returnConverterBridgeCopyBackupMediaOutcome(
  ffiInput: Native.ReturnFfiBridgeCopyBackupMediaOutcome
): BridgeCopyBackupMediaOutcome {
  return {
    mediaId: identity(ffiInput.media_id),
    result: returnConverterBridgeCopyBackupMediaResult(ffiInput.result),
  };
}

export function returnConverterBridgeCopyBackupMediaResult(
  ffiInput: Native.ReturnFfiBridgeCopyBackupMediaResult
): BridgeCopyBackupMediaResult {
  switch (ffiInput.__type) {
    case 0:
      return {
        success: identity(ffiInput.cdn),
      };
    case 1:
      return 'sourceNotFound';
    case 2:
      return 'wrongSourceLength';
    case 3:
      return 'outOfSpace';

    default:
      ffiInput satisfies never;
      throw new Error(
        'Unknown FFI return enum type for BridgeCopyBackupMediaResult'
      );
  }
}

export function returnConverterBridgeDeleteBackupMediaItem(
  ffiInput: Native.ReturnFfiBridgeDeleteBackupMediaItem
): BridgeDeleteBackupMediaItem {
  return {
    mediaId: identity(ffiInput.media_id),
    cdn: identity(ffiInput.cdn),
  };
}

export function returnConverterBridgeMediaBackupInfo(
  ffiInput: Native.ReturnFfiBridgeMediaBackupInfo
): BridgeMediaBackupInfo {
  return {
    backupDir: identity(ffiInput.backup_dir),
    mediaDir: identity(ffiInput.media_dir),
    usedSpace: identity(ffiInput.used_space),
  };
}

export function returnConverterBridgeMessageBackupInfo(
  ffiInput: Native.ReturnFfiBridgeMessageBackupInfo
): BridgeMessageBackupInfo {
  return {
    backupDir: identity(ffiInput.backup_dir),
    cdn: identity(ffiInput.cdn),
    backupName: identity(ffiInput.backup_name),
  };
}

export function returnConverterCopyBackupMediaNextChunk(
  ffiInput: Native.ReturnFfiCopyBackupMediaNextChunk
): CopyBackupMediaNextChunk {
  return {
    chunk: ((arr: Array<ReturnFfiBridgeCopyBackupMediaOutcome>) =>
      arr.map(returnConverterBridgeCopyBackupMediaOutcome))(ffiInput.chunk),
    termination: identity(ffiInput.termination),
  };
}

export function returnConverterCopyBackupMediaOut(
  ffiInput: Native.ReturnFfiCopyBackupMediaOut
): CopyBackupMediaOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        item: returnConverterBridgeCopyBackupMediaOutcome(ffiInput._0),
      };
    case 1:
      return 'invalidDataInStream';
    case 2:
      return 'credentialRejected';
    case 3:
      return 'credentialRejectedWithoutAppropriateServerInfo';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for CopyBackupMediaOut');
  }
}

export function returnConverterDeleteBackupMediaNextChunk(
  ffiInput: Native.ReturnFfiDeleteBackupMediaNextChunk
): DeleteBackupMediaNextChunk {
  return {
    chunk: ((arr: Array<ReturnFfiBridgeDeleteBackupMediaItem>) =>
      arr.map(returnConverterBridgeDeleteBackupMediaItem))(ffiInput.chunk),
    termination: identity(ffiInput.termination),
  };
}

export function returnConverterDeleteBackupMediaOut(
  ffiInput: Native.ReturnFfiDeleteBackupMediaOut
): DeleteBackupMediaOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        item: returnConverterBridgeDeleteBackupMediaItem(ffiInput._0),
      };
    case 1:
      return 'invalidDataInStream';
    case 2:
      return 'credentialRejected';
    case 3:
      return 'credentialRejectedWithoutAppropriateServerInfo';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for DeleteBackupMediaOut');
  }
}

export function returnConverterGetDevicesOut(
  ffiInput: Native.ReturnFfiGetDevicesOut
): GetDevicesOut {
  return {
    devices: ((arr: Array<ReturnFfiLinkedDeviceInternal>) =>
      arr.map(returnConverterLinkedDeviceInternal))(ffiInput.devices),
  };
}

export function returnConverterGetMediaBackupInfoOut(
  ffiInput: Native.ReturnFfiGetMediaBackupInfoOut
): GetMediaBackupInfoOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        success: returnConverterBridgeMediaBackupInfo(ffiInput._0),
      };
    case 1:
      return 'credentialRejected';
    case 2:
      return 'missingResponse';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for GetMediaBackupInfoOut');
  }
}

export function returnConverterGetMessageBackupInfoOut(
  ffiInput: Native.ReturnFfiGetMessageBackupInfoOut
): GetMessageBackupInfoOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        success: returnConverterBridgeMessageBackupInfo(ffiInput._0),
      };
    case 1:
      return 'credentialRejected';
    case 2:
      return 'missingResponse';

    default:
      ffiInput satisfies never;
      throw new Error(
        'Unknown FFI return enum type for GetMessageBackupInfoOut'
      );
  }
}

export function returnConverterLinkedDeviceInternal(
  ffiInput: Native.ReturnFfiLinkedDeviceInternal
): LinkedDeviceInternal {
  return {
    id: identity(ffiInput.id),
    encryptedName: identity(ffiInput.encrypted_name),
    lastSeen: identity(ffiInput.last_seen),
    registrationId: identity(ffiInput.registration_id),
    createdAtCiphertext: identity(ffiInput.created_at_ciphertext),
  };
}

export function returnConverterMyRemoteDeriveEnum(
  ffiInput: Native.ReturnFfiMyRemoteDeriveEnum
): MyRemoteDeriveEnum {
  switch (ffiInput.__type) {
    case 0:
      return 'unit';
    case 1:
      return {
        tuple: [identity(ffiInput._0), identity(ffiInput._1)],
      };
    case 2:
      return {
        record: {
          x: identity(ffiInput.x),
          y: identity(ffiInput.y),
        },
      };
    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for MyRemoteDeriveEnum');
  }
}

export function returnConverterMyRemoteDeriveStruct(
  ffiInput: Native.ReturnFfiMyRemoteDeriveStruct
): MyRemoteDeriveStruct {
  return {
    x: identity(ffiInput.x),
    y: identity(ffiInput.y),
  };
}

export function returnConverterMySimpleTestEnum(
  ffiInput: Native.ReturnFfiMySimpleTestEnum
): MySimpleTestEnum {
  switch (ffiInput.__type) {
    case 0:
      return 'a';
    case 1:
      return 'b';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for MySimpleTestEnum');
  }
}

export function returnConverterMyTestEnum(
  ffiInput: Native.ReturnFfiMyTestEnum
): MyTestEnum {
  switch (ffiInput.__type) {
    case 0:
      return 'unit';
    case 1:
      return {
        single: identity(ffiInput._0),
      };
    case 2:
      return {
        singleNamed: identity(ffiInput.x),
      };
    case 3:
      return {
        double: [identity(ffiInput._0), identity(ffiInput._1)],
      };
    case 4:
      return {
        record: {
          personName: identity(ffiInput.person_name),
          personAge: identity(ffiInput.person_age),
          position: returnConverterMyTestPoint(ffiInput.position),
          funStruct: returnConverterMyTestStruct(ffiInput.fun_struct),
        },
      };
    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for MyTestEnum');
  }
}

export function returnConverterMyTestPoint(
  ffiInput: Native.ReturnFfiMyTestPoint
): MyTestPoint {
  return [identity(ffiInput._0), identity(ffiInput._1)];
}

export function returnConverterMyTestStruct(
  ffiInput: Native.ReturnFfiMyTestStruct
): MyTestStruct {
  return {
    myNumericField: identity(ffiInput.my_numeric_field),
    myStringField: identity(ffiInput.my_string_field),
  };
}

export function returnConverterRemoveDeviceArgs(
  ffiInput: Native.ReturnFfiRemoveDeviceArgs
): RemoveDeviceArgs {
  return {
    id: identity(ffiInput.id),
  };
}

export function returnConverterRemoveDeviceOut(
  ffiInput: Native.ReturnFfiRemoveDeviceOut
): RemoveDeviceOut {
  switch (ffiInput.__type) {
    case 0:
      return 'success';

    default:
      ffiInput.__type satisfies never;
      throw new Error('Unknown FFI return enum type for RemoveDeviceOut');
  }
}

export function returnConverterReserveUsernameHashArgs(
  ffiInput: Native.ReturnFfiReserveUsernameHashArgs
): ReserveUsernameHashArgs {
  return {
    usernames: ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(
      ffiInput.usernames
    ),
  };
}

export function returnConverterReserveUsernameHashOut(
  ffiInput: Native.ReturnFfiReserveUsernameHashOut
): ReserveUsernameHashOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        success: identity(ffiInput._0),
      };
    case 1:
      return 'usernameNotAvailable';

    default:
      ffiInput satisfies never;
      throw new Error(
        'Unknown FFI return enum type for ReserveUsernameHashOut'
      );
  }
}

export function returnConverterSetDeviceNameArgs(
  ffiInput: Native.ReturnFfiSetDeviceNameArgs
): SetDeviceNameArgs {
  return {
    id: identity(ffiInput.id),
    encryptedName: identity(ffiInput.encrypted_name),
  };
}

export function returnConverterSetDeviceNameOut(
  ffiInput: Native.ReturnFfiSetDeviceNameOut
): SetDeviceNameOut {
  switch (ffiInput.__type) {
    case 0:
      return 'success';
    case 1:
      return 'deviceNotFound';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for SetDeviceNameOut');
  }
}

export function returnConverterSetUsernameLinkArgs(
  ffiInput: Native.ReturnFfiSetUsernameLinkArgs
): SetUsernameLinkArgs {
  return {
    usernameCiphertext: identity(ffiInput.username_ciphertext),
    keepLinkHandle: identity(ffiInput.keep_link_handle),
  };
}

export function returnConverterSetUsernameLinkOut(
  ffiInput: Native.ReturnFfiSetUsernameLinkOut
): SetUsernameLinkOut {
  switch (ffiInput.__type) {
    case 0:
      return {
        success: uuid.stringify(ffiInput._0),
      };
    case 1:
      return 'usernameNotSet';

    default:
      ffiInput satisfies never;
      throw new Error('Unknown FFI return enum type for SetUsernameLinkOut');
  }
}

export function returnConverterTestStreamChunk(
  ffiInput: Native.ReturnFfiTestStreamChunk
): TestStreamChunk {
  return {
    chunk: ((arr: Array<string>) => arr.map(identity))(ffiInput.chunk),
    termination: identity(ffiInput.termination),
  };
}

export function argConverterBridgeCopyBackupMediaItem(
  niceInput: BridgeCopyBackupMediaItem
): Native.ArgFfiBridgeCopyBackupMediaItem {
  const {
    sourceAttachmentCdn: source_attachment_cdn,
    sourceKey: source_key,
    objectLength: object_length,
    mediaId: media_id,
    encryptionKey: encryption_key,
  } = niceInput;
  return {
    source_attachment_cdn: identity(source_attachment_cdn),
    source_key: identity(source_key),
    object_length: identity(object_length),
    media_id: identity(media_id),
    encryption_key: identity(encryption_key),
  };
}

export function argConverterBridgeDeleteBackupMediaItem(
  niceInput: BridgeDeleteBackupMediaItem
): Native.ArgFfiBridgeDeleteBackupMediaItem {
  const { mediaId: media_id, cdn: cdn } = niceInput;
  return { media_id: identity(media_id), cdn: identity(cdn) };
}

export function argConverterMyRemoteDeriveEnum(
  niceInput: MyRemoteDeriveEnum
): Native.ArgFfiMyRemoteDeriveEnum {
  if (niceInput === 'unit') {
    return { __type: 0 };
  }

  if ('tuple' in niceInput) {
    const [_0, _1] = niceInput.tuple;
    return {
      __type: 1,
      _0: identity(_0),
      _1: identity(_1),
    };
  }

  if ('record' in niceInput) {
    const { x: x, y: y } = niceInput.record;
    return {
      __type: 2,
      x: identity(x),
      y: identity(y),
    };
  }

  niceInput satisfies never;
  throw new Error('Cannot match on MyRemoteDeriveEnum argument');
}

export function argConverterMyRemoteDeriveStruct(
  niceInput: MyRemoteDeriveStruct
): Native.ArgFfiMyRemoteDeriveStruct {
  const { x: x, y: y } = niceInput;
  return { x: identity(x), y: identity(y) };
}

export function argConverterMySimpleTestEnum(
  niceInput: MySimpleTestEnum
): Native.ArgFfiMySimpleTestEnum {
  if (niceInput === 'a') {
    return { __type: 0 };
  }

  if (niceInput === 'b') {
    return { __type: 1 };
  }

  niceInput satisfies never;
  throw new Error('Cannot match on MySimpleTestEnum argument');
}

export function argConverterMyTestEnum(
  niceInput: MyTestEnum
): Native.ArgFfiMyTestEnum {
  if (niceInput === 'unit') {
    return { __type: 0 };
  }

  if ('single' in niceInput) {
    return {
      __type: 1,
      _0: identity(niceInput.single),
    };
  }

  if ('singleNamed' in niceInput) {
    return {
      __type: 2,
      x: identity(niceInput.singleNamed),
    };
  }

  if ('double' in niceInput) {
    const [_0, _1] = niceInput.double;
    return {
      __type: 3,
      _0: identity(_0),
      _1: identity(_1),
    };
  }

  if ('record' in niceInput) {
    const {
      personName: person_name,
      personAge: person_age,
      position: position,
      funStruct: fun_struct,
    } = niceInput.record;
    return {
      __type: 4,
      person_name: identity(person_name),
      person_age: identity(person_age),
      position: argConverterMyTestPoint(position),
      fun_struct: argConverterMyTestStruct(fun_struct),
    };
  }

  niceInput satisfies never;
  throw new Error('Cannot match on MyTestEnum argument');
}

export function argConverterMyTestPoint(
  niceInput: MyTestPoint
): Native.ArgFfiMyTestPoint {
  const [_0, _1] = niceInput;
  return { _0: identity(_0), _1: identity(_1) };
}

export function argConverterMyTestStruct(
  niceInput: MyTestStruct
): Native.ArgFfiMyTestStruct {
  const { myNumericField: my_numeric_field, myStringField: my_string_field } =
    niceInput;
  return {
    my_numeric_field: identity(my_numeric_field),
    my_string_field: identity(my_string_field),
  };
}

export async function AuthenticatedChatConnection_clear_push_token({
  asyncContext,
  abortSignal,
  chat: chat,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_clear_push_token(
        asyncContext,
        identity(chat)
      )
    )
  );
}
export async function AuthenticatedChatConnection_clear_registration_lock({
  asyncContext,
  abortSignal,
  chat: chat,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_clear_registration_lock(
        asyncContext,
        identity(chat)
      )
    )
  );
}
export async function AuthenticatedChatConnection_delete_username_hash({
  asyncContext,
  abortSignal,
  chat: chat,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_delete_username_hash(
        asyncContext,
        identity(chat)
      )
    )
  );
}
export async function AuthenticatedChatConnection_delete_username_link({
  asyncContext,
  abortSignal,
  chat: chat,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_delete_username_link(
        asyncContext,
        identity(chat)
      )
    )
  );
}
export async function AuthenticatedChatConnection_get_devices({
  asyncContext,
  abortSignal,
  chat: chat,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
}): Promise<Array<LinkedDeviceInternal>> {
  return ((arr: Array<ReturnFfiLinkedDeviceInternal>) =>
    arr.map(returnConverterLinkedDeviceInternal))(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_get_devices(
        asyncContext,
        identity(chat)
      )
    )
  );
}
export async function AuthenticatedChatConnection_remove_device({
  asyncContext,
  abortSignal,
  chat: chat,
  deviceId: device_id,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  deviceId: DeviceId;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_remove_device(
        asyncContext,
        identity(chat),
        identity(device_id)
      )
    )
  );
}
export async function AuthenticatedChatConnection_reserve_username_hash({
  asyncContext,
  abortSignal,
  chat: chat,
  usernameHashes: username_hashes,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  usernameHashes: Array<Uint8Array<ArrayBuffer>>;
}): Promise<Uint8Array<ArrayBuffer>> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_reserve_username_hash(
        asyncContext,
        identity(chat),
        ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(
          username_hashes
        )
      )
    )
  );
}
export async function AuthenticatedChatConnection_set_device_name({
  asyncContext,
  abortSignal,
  chat: chat,
  deviceId: device_id,
  encryptedName: encrypted_name,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  deviceId: DeviceId;
  encryptedName: Uint8Array<ArrayBuffer>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_set_device_name(
        asyncContext,
        identity(chat),
        identity(device_id),
        identity(encrypted_name)
      )
    )
  );
}
export async function AuthenticatedChatConnection_set_discoverable_by_phone_number({
  asyncContext,
  abortSignal,
  chat: chat,
  discoverable: discoverable,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  discoverable: boolean;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_set_discoverable_by_phone_number(
        asyncContext,
        identity(chat),
        identity(discoverable)
      )
    )
  );
}
export async function AuthenticatedChatConnection_set_registration_lock({
  asyncContext,
  abortSignal,
  chat: chat,
  svrKey: svr_key,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  svrKey: Uint8Array<ArrayBuffer>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_set_registration_lock(
        asyncContext,
        identity(chat),
        identity(svr_key)
      )
    )
  );
}
export async function AuthenticatedChatConnection_set_registration_recovery_password({
  asyncContext,
  abortSignal,
  chat: chat,
  svrKey: svr_key,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  svrKey: Uint8Array<ArrayBuffer>;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_set_registration_recovery_password(
        asyncContext,
        identity(chat),
        identity(svr_key)
      )
    )
  );
}
export async function AuthenticatedChatConnection_set_username_link({
  asyncContext,
  abortSignal,
  chat: chat,
  usernameCiphertext: username_ciphertext,
  keepLinkHandle: keep_link_handle,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.AuthenticatedChatConnection>;
  usernameCiphertext: Uint8Array<ArrayBuffer>;
  keepLinkHandle: boolean;
}): Promise<uuid.Uuid> {
  return uuid.stringify(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.AuthenticatedChatConnection_set_username_link(
        asyncContext,
        identity(chat),
        identity(username_ciphertext),
        identity(keep_link_handle)
      )
    )
  );
}
export async function CopyBackupMediaStream_next({
  asyncContext,
  abortSignal,
  stream: stream,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  stream: Native.Wrapper<Native.CopyBackupMediaStream>;
}): Promise<CopyBackupMediaNextChunk> {
  return returnConverterCopyBackupMediaNextChunk(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.CopyBackupMediaStream_next(asyncContext, identity(stream))
    )
  );
}
export async function DeleteBackupMediaStream_next({
  asyncContext,
  abortSignal,
  stream: stream,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  stream: Native.Wrapper<Native.DeleteBackupMediaStream>;
}): Promise<DeleteBackupMediaNextChunk> {
  return returnConverterDeleteBackupMediaNextChunk(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.DeleteBackupMediaStream_next(asyncContext, identity(stream))
    )
  );
}

export function SvrKey_DeriveLoggingKey({
  svrKey: svr_key,
}: {
  svrKey: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.SvrKey_DeriveLoggingKey(identity(svr_key)));
}

export function SvrKey_DeriveRegistrationLock({
  svrKey: svr_key,
}: {
  svrKey: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.SvrKey_DeriveRegistrationLock(identity(svr_key)));
}

export function SvrKey_DeriveRegistrationRecoveryPassword({
  svrKey: svr_key,
}: {
  svrKey: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(
    Native.SvrKey_DeriveRegistrationRecoveryPassword(identity(svr_key))
  );
}

export function SvrKey_DeriveStorageServiceKey({
  svrKey: svr_key,
}: {
  svrKey: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.SvrKey_DeriveStorageServiceKey(identity(svr_key)));
}

export function TESTING_ClearPushTokenTests(): Array<GrpcTestCase<void, void>> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_ClearPushTokenTests());
}

export function TESTING_ClearRegistrationLockTests(): Array<
  GrpcTestCase<void, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_ClearRegistrationLockTests());
}

export function TESTING_CopyBackupMediaTests(): Array<
  GrpcTestCase<Array<BridgeCopyBackupMediaItem>, Array<CopyBackupMediaOut>>
> {
  return grpcTestCaseConverter(
    (arr: Array<ReturnFfiBridgeCopyBackupMediaItem>) =>
      arr.map(returnConverterBridgeCopyBackupMediaItem),
    (arr: Array<ReturnFfiCopyBackupMediaOut>) =>
      arr.map(returnConverterCopyBackupMediaOut)
  )(Native.TESTING_CopyBackupMediaTests());
}

export function TESTING_DeleteBackupMediaTests(): Array<
  GrpcTestCase<Array<BridgeDeleteBackupMediaItem>, Array<DeleteBackupMediaOut>>
> {
  return grpcTestCaseConverter(
    (arr: Array<ReturnFfiBridgeDeleteBackupMediaItem>) =>
      arr.map(returnConverterBridgeDeleteBackupMediaItem),
    (arr: Array<ReturnFfiDeleteBackupMediaOut>) =>
      arr.map(returnConverterDeleteBackupMediaOut)
  )(Native.TESTING_DeleteBackupMediaTests());
}

export function TESTING_DeleteUsernameHashTests(): Array<
  GrpcTestCase<void, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_DeleteUsernameHashTests());
}

export function TESTING_DeleteUsernameLinkTests(): Array<
  GrpcTestCase<void, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_DeleteUsernameLinkTests());
}

export function TESTING_GetDevicesTests(): Array<
  GrpcTestCase<void, GetDevicesOut>
> {
  return grpcTestCaseConverter(
    identity,
    returnConverterGetDevicesOut
  )(Native.TESTING_GetDevicesTests());
}

export function TESTING_GetMediaBackupInfoTests(): Array<
  GrpcTestCase<void, GetMediaBackupInfoOut>
> {
  return grpcTestCaseConverter(
    identity,
    returnConverterGetMediaBackupInfoOut
  )(Native.TESTING_GetMediaBackupInfoTests());
}

export function TESTING_GetMessageBackupInfoTests(): Array<
  GrpcTestCase<void, GetMessageBackupInfoOut>
> {
  return grpcTestCaseConverter(
    identity,
    returnConverterGetMessageBackupInfoOut
  )(Native.TESTING_GetMessageBackupInfoTests());
}

export function TESTING_MyRemoteDeriveEnum_identity({
  x: x,
}: {
  x: MyRemoteDeriveEnum;
}): MyRemoteDeriveEnum {
  return returnConverterMyRemoteDeriveEnum(
    Native.TESTING_MyRemoteDeriveEnum_identity(
      argConverterMyRemoteDeriveEnum(x)
    )
  );
}

export function TESTING_MyRemoteDeriveStruct_identity({
  x: x,
}: {
  x: MyRemoteDeriveStruct;
}): MyRemoteDeriveStruct {
  return returnConverterMyRemoteDeriveStruct(
    Native.TESTING_MyRemoteDeriveStruct_identity(
      argConverterMyRemoteDeriveStruct(x)
    )
  );
}

export function TESTING_MySimpleTestEnum_BridgeVec_identity({
  x: x,
}: {
  x: Array<MySimpleTestEnum>;
}): Array<MySimpleTestEnum> {
  return ((arr: Array<ReturnFfiMySimpleTestEnum>) =>
    arr.map(returnConverterMySimpleTestEnum))(
    Native.TESTING_MySimpleTestEnum_BridgeVec_identity(
      ((arr: Array<MySimpleTestEnum>) => arr.map(argConverterMySimpleTestEnum))(
        x
      )
    )
  );
}
export async function TESTING_MySimpleTestEnum_BridgeVec_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Array<MySimpleTestEnum>;
}): Promise<Array<MySimpleTestEnum>> {
  return ((arr: Array<ReturnFfiMySimpleTestEnum>) =>
    arr.map(returnConverterMySimpleTestEnum))(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_MySimpleTestEnum_BridgeVec_identity_async(
        asyncContext,
        ((arr: Array<MySimpleTestEnum>) =>
          arr.map(argConverterMySimpleTestEnum))(x)
      )
    )
  );
}

export function TESTING_MySimpleTestEnum_BridgeVec_to_string({
  x: x,
}: {
  x: Array<MySimpleTestEnum>;
}): string {
  return identity(
    Native.TESTING_MySimpleTestEnum_BridgeVec_to_string(
      ((arr: Array<MySimpleTestEnum>) => arr.map(argConverterMySimpleTestEnum))(
        x
      )
    )
  );
}

export function TESTING_MySimpleTestEnum_identity({
  x: x,
}: {
  x: MySimpleTestEnum;
}): MySimpleTestEnum {
  return returnConverterMySimpleTestEnum(
    Native.TESTING_MySimpleTestEnum_identity(argConverterMySimpleTestEnum(x))
  );
}
export async function TESTING_MySimpleTestEnum_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: MySimpleTestEnum;
}): Promise<MySimpleTestEnum> {
  return returnConverterMySimpleTestEnum(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_MySimpleTestEnum_identity_async(
        asyncContext,
        argConverterMySimpleTestEnum(x)
      )
    )
  );
}

export function TESTING_MySimpleTestEnum_to_string({
  x: x,
}: {
  x: MySimpleTestEnum;
}): string {
  return identity(
    Native.TESTING_MySimpleTestEnum_to_string(argConverterMySimpleTestEnum(x))
  );
}

export function TESTING_MyTestEnum_identity({
  x: x,
}: {
  x: MyTestEnum;
}): MyTestEnum {
  return returnConverterMyTestEnum(
    Native.TESTING_MyTestEnum_identity(argConverterMyTestEnum(x))
  );
}
export async function TESTING_MyTestEnum_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: MyTestEnum;
}): Promise<MyTestEnum> {
  return returnConverterMyTestEnum(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_MyTestEnum_identity_async(
        asyncContext,
        argConverterMyTestEnum(x)
      )
    )
  );
}

export function TESTING_MyTestEnum_to_string({
  x: x,
}: {
  x: MyTestEnum;
}): string {
  return identity(
    Native.TESTING_MyTestEnum_to_string(argConverterMyTestEnum(x))
  );
}

export function TESTING_MyTestPoint_identity({
  x: x,
}: {
  x: MyTestPoint;
}): MyTestPoint {
  return returnConverterMyTestPoint(
    Native.TESTING_MyTestPoint_identity(argConverterMyTestPoint(x))
  );
}
export async function TESTING_MyTestPoint_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: MyTestPoint;
}): Promise<MyTestPoint> {
  return returnConverterMyTestPoint(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_MyTestPoint_identity_async(
        asyncContext,
        argConverterMyTestPoint(x)
      )
    )
  );
}

export function TESTING_MyTestPoint_to_string({
  x: x,
}: {
  x: MyTestPoint;
}): string {
  return identity(
    Native.TESTING_MyTestPoint_to_string(argConverterMyTestPoint(x))
  );
}

export function TESTING_MyTestStruct_identity({
  x: x,
}: {
  x: MyTestStruct;
}): MyTestStruct {
  return returnConverterMyTestStruct(
    Native.TESTING_MyTestStruct_identity(argConverterMyTestStruct(x))
  );
}
export async function TESTING_MyTestStruct_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: MyTestStruct;
}): Promise<MyTestStruct> {
  return returnConverterMyTestStruct(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_MyTestStruct_identity_async(
        asyncContext,
        argConverterMyTestStruct(x)
      )
    )
  );
}

export function TESTING_MyTestStruct_to_string({
  x: x,
}: {
  x: MyTestStruct;
}): string {
  return identity(
    Native.TESTING_MyTestStruct_to_string(argConverterMyTestStruct(x))
  );
}

export function TESTING_RemoveDeviceTests(): Array<
  GrpcTestCase<RemoveDeviceArgs, RemoveDeviceOut>
> {
  return grpcTestCaseConverter(
    returnConverterRemoveDeviceArgs,
    returnConverterRemoveDeviceOut
  )(Native.TESTING_RemoveDeviceTests());
}

export function TESTING_ReserveUsernameHashTests(): Array<
  GrpcTestCase<ReserveUsernameHashArgs, ReserveUsernameHashOut>
> {
  return grpcTestCaseConverter(
    returnConverterReserveUsernameHashArgs,
    returnConverterReserveUsernameHashOut
  )(Native.TESTING_ReserveUsernameHashTests());
}

export function TESTING_ReturnIoError(): Error {
  return identity(Native.TESTING_ReturnIoError());
}

export function TESTING_ReturnSomeIoError({
  present: present,
}: {
  present: boolean;
}): Error | null {
  return identity(Native.TESTING_ReturnSomeIoError(identity(present)));
}

export function TESTING_SetDeviceNameTests(): Array<
  GrpcTestCase<SetDeviceNameArgs, SetDeviceNameOut>
> {
  return grpcTestCaseConverter(
    returnConverterSetDeviceNameArgs,
    returnConverterSetDeviceNameOut
  )(Native.TESTING_SetDeviceNameTests());
}

export function TESTING_SetDiscoverableByPhoneNumberTests(): Array<
  GrpcTestCase<boolean, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_SetDiscoverableByPhoneNumberTests());
}

export function TESTING_SetRegistrationLockTests(): Array<
  GrpcTestCase<Uint8Array<ArrayBuffer>, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_SetRegistrationLockTests());
}

export function TESTING_SetRegistrationRecoveryPasswordTests(): Array<
  GrpcTestCase<Uint8Array<ArrayBuffer>, void>
> {
  return grpcTestCaseConverter(
    identity,
    identity
  )(Native.TESTING_SetRegistrationRecoveryPasswordTests());
}

export function TESTING_SetUsernameLinkTests(): Array<
  GrpcTestCase<SetUsernameLinkArgs, SetUsernameLinkOut>
> {
  return grpcTestCaseConverter(
    returnConverterSetUsernameLinkArgs,
    returnConverterSetUsernameLinkOut
  )(Native.TESTING_SetUsernameLinkTests());
}

export function TESTING_TestStreamChunk_return(): TestStreamChunk {
  return returnConverterTestStreamChunk(
    Native.TESTING_TestStreamChunk_return()
  );
}

export function TESTING_TestingIntBox_Get({
  myIntBox: my_int_box,
}: {
  myIntBox: Native.Wrapper<Native.TestingIntBox>;
}): number {
  return identity(Native.TESTING_TestingIntBox_Get(identity(my_int_box)));
}
export async function TESTING_TokioAsyncContext_FutureSuccessBytes({
  asyncContext,
  abortSignal,
  count: count,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  count: number;
}): Promise<Uint8Array<ArrayBuffer>> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_TokioAsyncContext_FutureSuccessBytes(
        asyncContext,
        identity(count)
      )
    )
  );
}

export function TESTING_conversion_BridgeVecData32_identity({
  x: x,
}: {
  x: Array<Uint8Array<ArrayBuffer>>;
}): Array<Uint8Array<ArrayBuffer>> {
  return ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(
    Native.TESTING_conversion_BridgeVecData32_identity(
      ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(x)
    )
  );
}
export async function TESTING_conversion_BridgeVecData32_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Array<Uint8Array<ArrayBuffer>>;
}): Promise<Array<Uint8Array<ArrayBuffer>>> {
  return ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_BridgeVecData32_identity_async(
        asyncContext,
        ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(x)
      )
    )
  );
}

export function TESTING_conversion_BridgeVecData32_to_string({
  x: x,
}: {
  x: Array<Uint8Array<ArrayBuffer>>;
}): string {
  return identity(
    Native.TESTING_conversion_BridgeVecData32_to_string(
      ((arr: Array<Uint8Array<ArrayBuffer>>) => arr.map(identity))(x)
    )
  );
}

export function TESTING_conversion_BridgeVecString_identity({
  x: x,
}: {
  x: Array<string>;
}): Array<string> {
  return ((arr: Array<string>) => arr.map(identity))(
    Native.TESTING_conversion_BridgeVecString_identity(
      ((arr: Array<string>) => arr.map(identity))(x)
    )
  );
}
export async function TESTING_conversion_BridgeVecString_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Array<string>;
}): Promise<Array<string>> {
  return ((arr: Array<string>) => arr.map(identity))(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_BridgeVecString_identity_async(
        asyncContext,
        ((arr: Array<string>) => arr.map(identity))(x)
      )
    )
  );
}

export function TESTING_conversion_BridgeVecString_to_string({
  x: x,
}: {
  x: Array<string>;
}): string {
  return identity(
    Native.TESTING_conversion_BridgeVecString_to_string(
      ((arr: Array<string>) => arr.map(identity))(x)
    )
  );
}

export function TESTING_conversion_Data32_identity({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.TESTING_conversion_Data32_identity(identity(x)));
}
export async function TESTING_conversion_Data32_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Uint8Array<ArrayBuffer>;
}): Promise<Uint8Array<ArrayBuffer>> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_Data32_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_Data32_to_string({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): string {
  return identity(Native.TESTING_conversion_Data32_to_string(identity(x)));
}

export function TESTING_conversion_Data_VecU8_identity({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.TESTING_conversion_Data_VecU8_identity(identity(x)));
}
export async function TESTING_conversion_Data_VecU8_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Uint8Array<ArrayBuffer>;
}): Promise<Uint8Array<ArrayBuffer>> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_Data_VecU8_identity_async(
        asyncContext,
        identity(x)
      )
    )
  );
}

export function TESTING_conversion_Data_VecU8_to_string({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): string {
  return identity(Native.TESTING_conversion_Data_VecU8_to_string(identity(x)));
}

export function TESTING_conversion_Data_identity({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.TESTING_conversion_Data_identity(identity(x)));
}
export async function TESTING_conversion_Data_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: Uint8Array<ArrayBuffer>;
}): Promise<Uint8Array<ArrayBuffer>> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_Data_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_Data_to_string({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): string {
  return identity(Native.TESTING_conversion_Data_to_string(identity(x)));
}

export function TESTING_conversion_DeviceId_identity({
  x: x,
}: {
  x: DeviceId;
}): DeviceId {
  return identity(Native.TESTING_conversion_DeviceId_identity(identity(x)));
}
export async function TESTING_conversion_DeviceId_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: DeviceId;
}): Promise<DeviceId> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_DeviceId_identity_async(
        asyncContext,
        identity(x)
      )
    )
  );
}

export function TESTING_conversion_DeviceId_to_string({
  x: x,
}: {
  x: DeviceId;
}): string {
  return identity(Native.TESTING_conversion_DeviceId_to_string(identity(x)));
}

export function TESTING_conversion_ServiceId_identity({
  x: x,
}: {
  x: ServiceId;
}): ServiceId {
  return ServiceId.parseFromServiceIdFixedWidthBinary(
    Native.TESTING_conversion_ServiceId_identity(serviceIdArgConverter(x))
  );
}
export async function TESTING_conversion_ServiceId_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: ServiceId;
}): Promise<ServiceId> {
  return ServiceId.parseFromServiceIdFixedWidthBinary(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_ServiceId_identity_async(
        asyncContext,
        serviceIdArgConverter(x)
      )
    )
  );
}

export function TESTING_conversion_ServiceId_to_string({
  x: x,
}: {
  x: ServiceId;
}): string {
  return identity(
    Native.TESTING_conversion_ServiceId_to_string(serviceIdArgConverter(x))
  );
}

export function TESTING_conversion_Uuid_identity({
  x: x,
}: {
  x: uuid.Uuid;
}): uuid.Uuid {
  return uuid.stringify(Native.TESTING_conversion_Uuid_identity(uuid.parse(x)));
}
export async function TESTING_conversion_Uuid_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: uuid.Uuid;
}): Promise<uuid.Uuid> {
  return uuid.stringify(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_Uuid_identity_async(asyncContext, uuid.parse(x))
    )
  );
}

export function TESTING_conversion_Uuid_to_string({
  x: x,
}: {
  x: uuid.Uuid;
}): string {
  return identity(Native.TESTING_conversion_Uuid_to_string(uuid.parse(x)));
}

export function TESTING_conversion_bool_identity({
  x: x,
}: {
  x: boolean;
}): boolean {
  return identity(Native.TESTING_conversion_bool_identity(identity(x)));
}
export async function TESTING_conversion_bool_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: boolean;
}): Promise<boolean> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_bool_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_bool_to_string({
  x: x,
}: {
  x: boolean;
}): string {
  return identity(Native.TESTING_conversion_bool_to_string(identity(x)));
}

export function TESTING_conversion_i32_identity({
  x: x,
}: {
  x: number;
}): number {
  return identity(Native.TESTING_conversion_i32_identity(identity(x)));
}
export async function TESTING_conversion_i32_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: number;
}): Promise<number> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_i32_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_i32_to_string({
  x: x,
}: {
  x: number;
}): string {
  return identity(Native.TESTING_conversion_i32_to_string(identity(x)));
}

export function TESTING_conversion_string_identity({
  x: x,
}: {
  x: string;
}): string {
  return identity(Native.TESTING_conversion_string_identity(identity(x)));
}
export async function TESTING_conversion_string_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: string;
}): Promise<string> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_string_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_u16_identity({
  x: x,
}: {
  x: number;
}): number {
  return identity(Native.TESTING_conversion_u16_identity(identity(x)));
}
export async function TESTING_conversion_u16_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: number;
}): Promise<number> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_u16_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_u16_to_string({
  x: x,
}: {
  x: number;
}): string {
  return identity(Native.TESTING_conversion_u16_to_string(identity(x)));
}

export function TESTING_conversion_u8_identity({
  x: x,
}: {
  x: number;
}): number {
  return identity(Native.TESTING_conversion_u8_identity(identity(x)));
}
export async function TESTING_conversion_u8_identity_async({
  asyncContext,
  abortSignal,
  x: x,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  x: number;
}): Promise<number> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.TESTING_conversion_u8_identity_async(asyncContext, identity(x))
    )
  );
}

export function TESTING_conversion_u8_to_string({
  x: x,
}: {
  x: number;
}): string {
  return identity(Native.TESTING_conversion_u8_to_string(identity(x)));
}
export async function UnauthenticatedChatConnection_account_exists({
  asyncContext,
  abortSignal,
  chat: chat,
  account: account,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  account: ServiceId;
}): Promise<boolean> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_account_exists(
        asyncContext,
        identity(chat),
        serviceIdArgConverter(account)
      )
    )
  );
}

export function UnauthenticatedChatConnection_backup_copy_media({
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  items: items,
  rng: rng,
}: {
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  items: Array<BridgeCopyBackupMediaItem>;
  rng: Rng | undefined;
}): (
  asyncContext: TokioAsyncContext
) => ReadableStream<Native.ReturnFfiBridgeCopyBackupMediaOutcome> {
  return copyBackupMediaStreamConverter(
    Native.UnauthenticatedChatConnection_backup_copy_media(
      identity(chat),
      ByteArray.prototype.getContents.call(credential),
      ByteArray.prototype.getContents.call(server_keys),
      identity(signing_key),
      ((arr: Array<BridgeCopyBackupMediaItem>) =>
        arr.map(argConverterBridgeCopyBackupMediaItem))(items),
      ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
    )
  );
}
export async function UnauthenticatedChatConnection_backup_delete_all({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_delete_all(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}

export function UnauthenticatedChatConnection_backup_delete_media({
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  items: items,
  rng: rng,
}: {
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  items: Array<BridgeDeleteBackupMediaItem>;
  rng: Rng | undefined;
}): (
  asyncContext: TokioAsyncContext
) => ReadableStream<Native.ReturnFfiBridgeDeleteBackupMediaItem> {
  return deleteBackupMediaStreamConverter(
    Native.UnauthenticatedChatConnection_backup_delete_media(
      identity(chat),
      ByteArray.prototype.getContents.call(credential),
      ByteArray.prototype.getContents.call(server_keys),
      identity(signing_key),
      ((arr: Array<BridgeDeleteBackupMediaItem>) =>
        arr.map(argConverterBridgeDeleteBackupMediaItem))(items),
      ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
    )
  );
}
export async function UnauthenticatedChatConnection_backup_get_cdn_credentials({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  cdn: cdn,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  cdn: number;
  rng: Rng | undefined;
}): Promise<CdnCredentials> {
  return cdnCredentialReturnConverter(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_cdn_credentials(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        identity(cdn),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
export async function UnauthenticatedChatConnection_backup_get_media_backup_info({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<BridgeMediaBackupInfo> {
  return returnConverterBridgeMediaBackupInfo(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_media_backup_info(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
export async function UnauthenticatedChatConnection_backup_get_message_backup_info({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<BridgeMessageBackupInfo> {
  return returnConverterBridgeMessageBackupInfo(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_message_backup_info(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
export async function UnauthenticatedChatConnection_backup_get_svrb_credentials({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<[string, string]> {
  return (([a, b]) => [identity(a), identity(b)])(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_svrb_credentials(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
export async function UnauthenticatedChatConnection_backup_refresh({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_refresh(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
export async function UnauthenticatedChatConnection_backup_set_public_key({
  asyncContext,
  abortSignal,
  chat: chat,
  credential: credential,
  serverKeys: server_keys,
  signingKey: signing_key,
  rng: rng,
}: {
  asyncContext: TokioAsyncContext;
  abortSignal?: AbortSignal;
  chat: Native.Wrapper<Native.UnauthenticatedChatConnection>;
  credential: zkgroup.BackupAuthCredential;
  serverKeys: zkgroup.GenericServerPublicParams;
  signingKey: Native.Wrapper<Native.PrivateKey>;
  rng: Rng | undefined;
}): Promise<void> {
  return identity(
    await asyncContext.makeCancellable(
      abortSignal,
      Native.UnauthenticatedChatConnection_backup_set_public_key(
        asyncContext,
        identity(chat),
        ByteArray.prototype.getContents.call(credential),
        ByteArray.prototype.getContents.call(server_keys),
        identity(signing_key),
        ((__rng) => __rng?.__deterministicRngSeedForTesting ?? -1)(rng)
      )
    )
  );
}
