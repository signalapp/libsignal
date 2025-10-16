//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';
import ServerPublicParams from '../ServerPublicParams.js';
import ReceiptCredential from './ReceiptCredential.js';
import ReceiptCredentialPresentation from './ReceiptCredentialPresentation.js';
import ReceiptCredentialRequestContext from './ReceiptCredentialRequestContext.js';
import ReceiptCredentialResponse from './ReceiptCredentialResponse.js';
import ReceiptSerial from './ReceiptSerial.js';

export default class ClientZkReceiptOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  createReceiptCredentialRequestContext(
    receiptSerial: ReceiptSerial
  ): ReceiptCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);
    return this.createReceiptCredentialRequestContextWithRandom(
      random,
      receiptSerial
    );
  }

  createReceiptCredentialRequestContextWithRandom(
    random: Uint8Array,
    receiptSerial: ReceiptSerial
  ): ReceiptCredentialRequestContext {
    return new ReceiptCredentialRequestContext(
      Native.ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
        this.serverPublicParams,
        random,
        receiptSerial.getContents()
      )
    );
  }

  receiveReceiptCredential(
    receiptCredentialRequestContext: ReceiptCredentialRequestContext,
    receiptCredentialResponse: ReceiptCredentialResponse
  ): ReceiptCredential {
    return new ReceiptCredential(
      Native.ServerPublicParams_ReceiveReceiptCredential(
        this.serverPublicParams,
        receiptCredentialRequestContext.getContents(),
        receiptCredentialResponse.getContents()
      )
    );
  }

  createReceiptCredentialPresentation(
    receiptCredential: ReceiptCredential
  ): ReceiptCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.createReceiptCredentialPresentationWithRandom(
      random,
      receiptCredential
    );
  }

  createReceiptCredentialPresentationWithRandom(
    random: Uint8Array,
    receiptCredential: ReceiptCredential
  ): ReceiptCredentialPresentation {
    return new ReceiptCredentialPresentation(
      Native.ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
        this.serverPublicParams,
        random,
        receiptCredential.getContents()
      )
    );
  }
}
