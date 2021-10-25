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
import ReceiptCredentialRequest from "./ReceiptCredentialRequest";

export default class ReceiptCredentialRequestContext extends ByteArray {

    static SIZE = 177;

    constructor(contents: FFICompatArrayType) {
        super(contents, ReceiptCredentialRequestContext.SIZE, true);

        const ffi_return = Native.FFI_ReceiptCredentialRequestContext_checkValidContents(this.contents, this.contents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }
    }

    getRequest(): ReceiptCredentialRequest {
        const newContents = new FFICompatArray(ReceiptCredentialRequest.SIZE);

        const ffi_return = Native.FFI_ReceiptCredentialRequestContext_getRequest(this.contents, this.contents.length, newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }

        return new ReceiptCredentialRequest(newContents);
    }
}
