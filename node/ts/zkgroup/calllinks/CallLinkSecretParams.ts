//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import CallLinkPublicParams from './CallLinkPublicParams';

export default class CallLinkSecretParams extends ByteArray {
  private readonly __type?: never;

  static deriveFromRootKey(callLinkRootKey: Buffer): CallLinkSecretParams {
    return new CallLinkSecretParams(
      Native.CallLinkSecretParams_DeriveFromRootKey(callLinkRootKey)
    );
  }

  constructor(contents: Buffer) {
    super(contents, Native.CallLinkSecretParams_CheckValidContents);
  }

  getPublicParams(): CallLinkPublicParams {
    return new CallLinkPublicParams(
      Native.CallLinkSecretParams_GetPublicParams(this.contents)
    );
  }
}
