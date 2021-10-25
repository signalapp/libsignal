/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import ByteArray from '../internal/ByteArray';
import FFICompatArray, {FFICompatArrayType} from '../internal/FFICompatArray';
import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import Native, {FFI_RETURN_INPUT_ERROR, FFI_RETURN_OK} from '../internal/Native';

export default class ReceiptCredential extends ByteArray {

    static SIZE = 129;

    constructor(contents: FFICompatArrayType) {
        super(contents, ReceiptCredential.SIZE, true);

        const ffi_return = Native.FFI_ReceiptCredential_checkValidContents(this.contents, this.contents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }
    }

    getReceiptExpirationTime(): string | number {
        const newContents = new FFICompatArray(Buffer.alloc(8));

        const ffi_return = Native.FFI_ReceiptCredential_getReceiptExpirationTime(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return newContents.buffer.readUInt64BE(0);
    }

    getReceiptLevel(): string | number {
        const newContents = new FFICompatArray(Buffer.alloc(8));

        const ffi_return = Native.FFI_ReceiptCredential_getReceiptLevel(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return newContents.buffer.readUInt64BE(0);
    }
}
