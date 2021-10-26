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

export default class ReceiptCredentialRequest extends ByteArray {

    static SIZE = 97;

    constructor(contents: Buffer) {
        super(contents, ReceiptCredentialRequest.SIZE, true);
        NativeImpl.ReceiptCredentialRequest_CheckValidContents(contents);
    }
}
