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

export default class ReceiptCredential extends ByteArray {

    static SIZE = 129;

    constructor(contents: Buffer) {
        super(contents, ReceiptCredential.SIZE, true);
        NativeImpl.ReceiptCredential_CheckValidContents(contents);
    }

    getReceiptExpirationTime(): bigint {
        return NativeImpl.ReceiptCredential_GetReceiptExpirationTime(
            this.contents
        ).readBigUInt64BE();
    }
  
    getReceiptLevel(): bigint {
        return NativeImpl.ReceiptCredential_GetReceiptLevel(
            this.contents
        ).readBigUInt64BE();
    }
}
