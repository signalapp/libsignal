//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ReceiptCredentialRequest extends ByteArray {

    static SIZE = 97;

    constructor(contents: Buffer) {
        super(contents, ReceiptCredentialRequest.SIZE, true);
        NativeImpl.ReceiptCredentialRequest_CheckValidContents(contents);
    }
}
