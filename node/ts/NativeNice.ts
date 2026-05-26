//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

import * as Native from './Native.js';
import { ServiceId } from './Address.js';
import { TokioAsyncContext } from './net.js';
import { identity, serviceIdArgConverter } from './NiceConverters.js';

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

export function TESTING_conversion_Data_identity({
  x: x,
}: {
  x: Uint8Array<ArrayBuffer>;
}): Uint8Array<ArrayBuffer> {
  return identity(Native.TESTING_conversion_Data_identity(identity(x)));
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

export function TESTING_conversion_u16_identity({
  x: x,
}: {
  x: number;
}): number {
  return identity(Native.TESTING_conversion_u16_identity(identity(x)));
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
