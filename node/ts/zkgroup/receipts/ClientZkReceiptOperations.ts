//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';
import ServerPublicParams from '../ServerPublicParams';
import ReceiptCredential from './ReceiptCredential';
import ReceiptCredentialPresentation from './ReceiptCredentialPresentation';
import ReceiptCredentialRequestContext from './ReceiptCredentialRequestContext';
import ReceiptCredentialResponse from './ReceiptCredentialResponse';
import ReceiptSerial from './ReceiptSerial';

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
    random: Buffer,
    receiptSerial: ReceiptSerial
  ): ReceiptCredentialRequestContext {
    return new ReceiptCredentialRequestContext(
      Native.ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
        this.serverPublicParams.getContents(),
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
        this.serverPublicParams.getContents(),
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
    random: Buffer,
    receiptCredential: ReceiptCredential
  ): ReceiptCredentialPresentation {
    return new ReceiptCredentialPresentation(
      Native.ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        receiptCredential.getContents()
      )
    );
  }
}
