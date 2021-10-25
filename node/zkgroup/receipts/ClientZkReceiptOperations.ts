/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import {randomBytes} from 'crypto';
import FFICompatArray, {FFICompatArrayType} from '../internal/FFICompatArray';
import ZkGroupError from '../errors/ZkGroupError';
import {RANDOM_LENGTH} from '../internal/Constants';
import Native, {FFI_RETURN_OK} from '../internal/Native';
import ServerPublicParams from '../ServerPublicParams';
import ReceiptCredential from "./ReceiptCredential";
import ReceiptCredentialPresentation from "./ReceiptCredentialPresentation";
import ReceiptCredentialRequestContext from "./ReceiptCredentialRequestContext";
import ReceiptCredentialResponse from "./ReceiptCredentialResponse";
import ReceiptSerial from "./ReceiptSerial";

export default class ClientZkReceiptOperations {

    serverPublicParams: ServerPublicParams

    constructor(serverPublicParams: ServerPublicParams) {
        this.serverPublicParams = serverPublicParams;
    }

    createReceiptCredentialRequestContext(receiptSerial: ReceiptSerial): ReceiptCredentialRequestContext {
        const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));
        return this.createReceiptCredentialRequestContextWithRandom(random, receiptSerial);
    }

    createReceiptCredentialRequestContextWithRandom(random: FFICompatArrayType, receiptSerial: ReceiptSerial): ReceiptCredentialRequestContext {
        const newContents = new FFICompatArray(ReceiptCredentialRequestContext.SIZE);
        const serverPublicParamsContents = this.serverPublicParams.getContents();
        const receiptSerialContents = receiptSerial.getContents();

        const ffi_return = Native.FFI_ServerPublicParams_createReceiptCredentialRequestContextDeterministic(
            serverPublicParamsContents, serverPublicParamsContents.length,
            random, random.length,
            receiptSerialContents, receiptSerialContents.length,
            newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return new ReceiptCredentialRequestContext(newContents);
    }

    receiveReceiptCredential(receiptCredentialRequestContext: ReceiptCredentialRequestContext, receiptCredentialResponse: ReceiptCredentialResponse): ReceiptCredential {
        const newContents = new FFICompatArray(ReceiptCredential.SIZE);
        const serverPublicParamsContents = this.serverPublicParams.getContents();
        const receiptCredentialRequestContextContents = receiptCredentialRequestContext.getContents();
        const receiptCredentialResponseContents = receiptCredentialResponse.getContents();

        const ffi_return = Native.FFI_ServerPublicParams_receiveReceiptCredential(
            serverPublicParamsContents, serverPublicParamsContents.length,
            receiptCredentialRequestContextContents, receiptCredentialRequestContextContents.length,
            receiptCredentialResponseContents, receiptCredentialResponseContents.length,
            newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return new ReceiptCredential(newContents);
    }

    createReceiptCredentialPresentation(receiptCredential: ReceiptCredential): ReceiptCredentialPresentation {
        const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));
        return this.createReceiptCredentialPresentationWithRandom(random, receiptCredential);
    }

    createReceiptCredentialPresentationWithRandom(random: FFICompatArrayType, receiptCredential: ReceiptCredential): ReceiptCredentialPresentation {
        const newContents = new FFICompatArray(ReceiptCredentialPresentation.SIZE);
        const serverPublicParamsContents = this.serverPublicParams.getContents();
        const receiptCredentialContents = receiptCredential.getContents();

        const ffi_return = Native.FFI_ServerPublicParams_createReceiptCredentialPresentationDeterministic(
            serverPublicParamsContents, serverPublicParamsContents.length,
            random, random.length,
            receiptCredentialContents, receiptCredentialContents.length,
            newContents, newContents.length);

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError("FFI_RETURN!=OK");
        }

        return new ReceiptCredentialPresentation(newContents);
    }
}
