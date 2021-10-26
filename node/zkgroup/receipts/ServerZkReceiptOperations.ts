/*
 *
 * Copyright (C) 2021 Signal Messenger, LLC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

import {randomBytes} from 'crypto';
import NativeImpl from '../../NativeImpl';
import { RANDOM_LENGTH } from '../internal/Constants';
import { bufferFromBigUInt64BE } from '../internal/BigIntUtil';
import ServerSecretParams from '../ServerSecretParams';
import ReceiptCredentialRequest from "./ReceiptCredentialRequest";
import ReceiptCredentialResponse from "./ReceiptCredentialResponse";
import ReceiptCredentialPresentation from "./ReceiptCredentialPresentation";

export default class ServerZkReceiptOperations {

    serverSecretParams: ServerSecretParams;

    constructor(serverSecretParams: ServerSecretParams) {
        this.serverSecretParams = serverSecretParams;
    }

    issueReceiptCredential(receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: bigint, receiptLevel: bigint): ReceiptCredentialResponse {
        const random = randomBytes(RANDOM_LENGTH);
        return this.issueReceiptCredentialWithRandom(random, receiptCredentialRequest, receiptExpirationTime, receiptLevel);
    }

    issueReceiptCredentialWithRandom(random: Buffer, receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: bigint, receiptLevel: bigint): ReceiptCredentialResponse {
        return new ReceiptCredentialResponse(NativeImpl.ServerSecretParams_IssueReceiptCredentialDeterministic(this.serverSecretParams.getContents(), random, receiptCredentialRequest.getContents(), bufferFromBigUInt64BE(receiptExpirationTime), bufferFromBigUInt64BE(receiptLevel)));
    }

    verifyReceiptCredentialPresentation(receiptCredentialPresentation: ReceiptCredentialPresentation) {
        NativeImpl.ServerSecretParams_VerifyReceiptCredentialPresentation(this.serverSecretParams.getContents(), receiptCredentialPresentation.getContents())
    }
}
