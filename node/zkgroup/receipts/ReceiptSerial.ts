/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import ByteArray from "../internal/ByteArray";
import {FFICompatArrayType} from "../internal/FFICompatArray";

export default class ReceiptSerial extends ByteArray {

    static SIZE = 16;

    constructor(contents: FFICompatArrayType) {
        super(contents, ReceiptSerial.SIZE, true);
    }
}
