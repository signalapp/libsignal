/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import ReceiptCredentialRequest from "./ReceiptCredentialRequest";

export default class ReceiptCredentialRequestContext extends ByteArray {

    static SIZE = 177;

    constructor(contents: Buffer) {
        super(contents, ReceiptCredentialRequestContext.SIZE, true);
        NativeImpl.ReceiptCredentialRequestContext_CheckValidContents(contents);
    }

    getRequest(): ReceiptCredentialRequest {
        return new ReceiptCredentialRequest(NativeImpl.ReceiptCredentialRequestContext_GetRequest(this.contents));
    }
}
