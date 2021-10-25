/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import ByteArray from '../internal/ByteArray';
import {FFICompatArrayType} from '../internal/FFICompatArray';
import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import Native, {FFI_RETURN_INPUT_ERROR, FFI_RETURN_OK} from '../internal/Native';

export default class ReceiptCredentialResponse extends ByteArray {

    static SIZE = 409;

    constructor(contents: FFICompatArrayType) {
        super(contents, ReceiptCredentialResponse.SIZE, true);

        const ffi_return = Native.FFI_ReceiptCredentialResponse_checkValidContents(this.contents, this.contents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }
    }
}
