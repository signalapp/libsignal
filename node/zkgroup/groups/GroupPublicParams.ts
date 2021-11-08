//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import GroupIdentifier from './GroupIdentifier';

export default class GroupPublicParams extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, NativeImpl.GroupPublicParams_CheckValidContents);
  }

  getGroupIdentifier(): GroupIdentifier {
    return new GroupIdentifier(
      NativeImpl.GroupPublicParams_GetGroupIdentifier(this.contents)
    );
  }
}
