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
import ReceiptSerial from "./ReceiptSerial";

export default class ReceiptCredentialPresentation extends ByteArray {

    static SIZE = 329;

    constructor(contents: Buffer) {
        super(contents, ReceiptCredentialPresentation.SIZE, true);
        NativeImpl.ReceiptCredentialPresentation_CheckValidContents(contents);
    }

    getReceiptExpirationTime(): bigint {
        return NativeImpl.ReceiptCredentialPresentation_GetReceiptExpirationTime(
            this.contents
        ).readBigUInt64BE();
    }

    getReceiptLevel(): bigint {
        return NativeImpl.ReceiptCredentialPresentation_GetReceiptLevel(
            this.contents
        ).readBigUInt64BE();
    }

    getReceiptSerialBytes(): ReceiptSerial {
        return new ReceiptSerial(NativeImpl.ReceiptCredentialPresentation_GetReceiptSerial(this.contents));
    }
}
