//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import GroupSendCredential from './GroupSendCredential';
import GroupSecretParams from '../groups/GroupSecretParams';
import ServerSecretParams from '../ServerSecretParams';
import ServerPublicParams from '../ServerPublicParams';
import UuidCiphertext from '../groups/UuidCiphertext';
import { Aci, ServiceId } from '../../Address';

export default class GroupSendCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredentialResponse_CheckValidContents);
  }

  private static defaultExpiration(): Date {
    const expirationInSeconds =
      Native.GroupSendCredentialResponse_DefaultExpirationBasedOnCurrentTime();
    return new Date(expirationInSeconds * 1000);
  }

  static issueCredential(
    groupMembers: UuidCiphertext[],
    requestingMember: UuidCiphertext,
    params: ServerSecretParams
  ): GroupSendCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithExpirationAndRandom(
      groupMembers,
      requestingMember,
      this.defaultExpiration(),
      params,
      random
    );
  }

  static issueCredentialWithExpirationAndRandom(
    groupMembers: UuidCiphertext[],
    requestingMember: UuidCiphertext,
    expiration: Date,
    params: ServerSecretParams,
    random: Buffer
  ): GroupSendCredentialResponse {
    const uuidCiphertextLen = requestingMember.contents.length;
    const concatenated = Buffer.alloc(groupMembers.length * uuidCiphertextLen);
    let offset = 0;
    for (const member of groupMembers) {
      if (member.contents.length !== uuidCiphertextLen) {
        throw TypeError('UuidCiphertext with unexpected length');
      }
      concatenated.set(member.contents, offset);
      offset += uuidCiphertextLen;
    }

    return new GroupSendCredentialResponse(
      Native.GroupSendCredentialResponse_IssueDeterministic(
        concatenated,
        requestingMember.contents,
        Math.floor(expiration.getTime() / 1000),
        params.contents,
        random
      )
    );
  }

  receive(
    groupMembers: ServiceId[],
    localUser: Aci,
    serverParams: ServerPublicParams,
    groupParams: GroupSecretParams,
    now: Date = new Date()
  ): GroupSendCredential {
    return new GroupSendCredential(
      Native.GroupSendCredentialResponse_Receive(
        this.contents,
        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
        localUser.getServiceIdFixedWidthBinary(),
        Math.floor(now.getTime() / 1000),
        serverParams.contents,
        groupParams.contents
      )
    );
  }
}
