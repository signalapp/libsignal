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
import ReceiptSerial from "./ReceiptSerial";

export default class ReceiptCredentialPresentation extends ByteArray {

    static SIZE = 329;

    constructor(contents: FFICompatArrayType) {
        super(contents, ReceiptCredentialPresentation.SIZE, true);

        const ffi_return = Native.FFI_ReceiptCredentialPresentation_checkValidContents(this.contents, this.contents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }
    }

    getReceiptExpirationTime(): string | number {
        const newContents = new FFICompatArray(Buffer.alloc(8));

        const ffi_return = Native.FFI_ReceiptCredentialPresentation_getReceiptExpirationTime(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return newContents.buffer.readUInt64BE(0);
    }

    getReceiptLevel(): string | number {
        const newContents = new FFICompatArray(Buffer.alloc(8));

        const ffi_return = Native.FFI_ReceiptCredentialPresentation_getReceiptLevel(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return newContents.buffer.readUInt64BE(0);
    }

    getReceiptSerialBytes(): ReceiptSerial {
        const newContents = new FFICompatArray(Buffer.alloc(ReceiptSerial.SIZE));

        const ffi_return = Native.FFI_ReceiptCredentialPresentation_getReceiptSerial(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return new ReceiptSerial(newContents);
    }
}
