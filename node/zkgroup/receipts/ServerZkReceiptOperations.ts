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
import VerificationFailedException from '../errors/VerificationFailedException';
import ZkGroupError from '../errors/ZkGroupError';
import Native, {FFI_RETURN_INPUT_ERROR, FFI_RETURN_OK} from '../internal/Native';
import {RANDOM_LENGTH} from '../internal/Constants';
import ServerSecretParams from '../ServerSecretParams';
import ReceiptCredentialRequest from "./ReceiptCredentialRequest";
import ReceiptCredentialResponse from "./ReceiptCredentialResponse";
import ReceiptCredentialPresentation from "./ReceiptCredentialPresentation";

export default class ServerZkReceiptOperations {

    serverSecretParams: ServerSecretParams;

    constructor(serverSecretParams: ServerSecretParams) {
        this.serverSecretParams = serverSecretParams;
    }

    issueReceiptCredential(receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: string, receiptLevel: string): ReceiptCredentialResponse {
        const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));
        return this.issueReceiptCredentialWithRandom(random, receiptCredentialRequest, receiptExpirationTime, receiptLevel);
    }

    issueReceiptCredentialWithRandom(random: FFICompatArrayType, receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: string, receiptLevel: string): ReceiptCredentialResponse {
        const newContents = new FFICompatArray(ReceiptCredentialResponse.SIZE);
        const serverSecretParamsContents = this.serverSecretParams.getContents();
        const receiptCredentialRequestContents = receiptCredentialRequest.getContents();

        const ffi_return = Native.FFI_ServerSecretParams_issueReceiptCredentialDeterministic(
            serverSecretParamsContents, serverSecretParamsContents.length,
            random, random.length,
            receiptCredentialRequestContents, receiptCredentialRequestContents.length,
            receiptExpirationTime,
            receiptLevel,
            newContents, newContents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }

        return new ReceiptCredentialResponse(newContents);
    }

    verifyReceiptCredentialPresentation(receiptCredentialPresentation: ReceiptCredentialPresentation) {
        const serverSecretParamsContents = this.serverSecretParams.getContents();
        const receiptCredentialPresentationContents = receiptCredentialPresentation.getContents();

        const ffi_return = Native.FFI_ServerSecretParams_verifyReceiptCredentialPresentation(
            serverSecretParamsContents, serverSecretParamsContents.length,
            receiptCredentialPresentationContents, receiptCredentialPresentationContents.length);

        if (ffi_return == FFI_RETURN_INPUT_ERROR) {
            throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
        }

        if (ffi_return != FFI_RETURN_OK) {
            throw new ZkGroupError('FFI_RETURN!=OK');
        }
    }
}
