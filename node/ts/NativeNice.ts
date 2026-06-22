//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

import * as Native from './Native.js';
import { type GrpcTestCase } from './Native.js';
import { ServiceId } from './Address.js';
import * as zkgroup from './zkgroup/index.js';
import ByteArray from './zkgroup/internal/ByteArray.js';
import { TokioAsyncContext } from './net.js';
import { CdnCredentials } from './net/chat/CdnCredentials.js';
import {
  cdnCredentialReturnConverter,
  identity,
  serviceIdArgConverter,
  grpcTestCaseConverter,
} from './NiceConverters.js';
import { Rng } from './RngForTesting.js';

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

export type SetDeviceNameArgs = {
  id: number;
  encryptedName: Uint8Array<ArrayBuffer>;
};

export type SetDeviceNameOut = 'success' | 'deviceNotFound';

function returnConverterMyRemoteDeriveEnum(
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

function returnConverterMyRemoteDeriveStruct(
  ffiInput: Native.ReturnFfiMyRemoteDeriveStruct
): MyRemoteDeriveStruct {
  return {
    x: identity(ffiInput.x),
    y: identity(ffiInput.y),
  };
}

function returnConverterMySimpleTestEnum(
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

function returnConverterMyTestEnum(
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

function returnConverterMyTestPoint(
  ffiInput: Native.ReturnFfiMyTestPoint
): MyTestPoint {
  return [identity(ffiInput._0), identity(ffiInput._1)];
}

function returnConverterMyTestStruct(
  ffiInput: Native.ReturnFfiMyTestStruct
): MyTestStruct {
  return {
    myNumericField: identity(ffiInput.my_numeric_field),
    myStringField: identity(ffiInput.my_string_field),
  };
}

function returnConverterSetDeviceNameArgs(
  ffiInput: Native.ReturnFfiSetDeviceNameArgs
): SetDeviceNameArgs {
  return {
    id: identity(ffiInput.id),
    encryptedName: identity(ffiInput.encrypted_name),
  };
}

function returnConverterSetDeviceNameOut(
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

function argConverterMyRemoteDeriveEnum(
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

function argConverterMyRemoteDeriveStruct(
  niceInput: MyRemoteDeriveStruct
): Native.ArgFfiMyRemoteDeriveStruct {
  const { x: x, y: y } = niceInput;
  return { x: identity(x), y: identity(y) };
}

function argConverterMySimpleTestEnum(
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

function argConverterMyTestEnum(
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

function argConverterMyTestPoint(
  niceInput: MyTestPoint
): Native.ArgFfiMyTestPoint {
  const [_0, _1] = niceInput;
  return { _0: identity(_0), _1: identity(_1) };
}

function argConverterMyTestStruct(
  niceInput: MyTestStruct
): Native.ArgFfiMyTestStruct {
  const { myNumericField: my_numeric_field, myStringField: my_string_field } =
    niceInput;
  return {
    my_numeric_field: identity(my_numeric_field),
    my_string_field: identity(my_string_field),
  };
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
  deviceId: number;
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

export function TESTING_SetDeviceNameTests(): Array<
  GrpcTestCase<SetDeviceNameArgs, SetDeviceNameOut>
> {
  return grpcTestCaseConverter(
    returnConverterSetDeviceNameArgs,
    returnConverterSetDeviceNameOut
  )(Native.TESTING_SetDeviceNameTests());
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
