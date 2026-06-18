//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';
import ByteArray from './internal/ByteArray.js';
import { RANDOM_LENGTH } from './internal/Constants.js';
import * as Native from '../Native.js';
import ServerSecretParams from './ServerSecretParams.js';
import ServerPublicParams from './ServerPublicParams.js';
import { type LibSignalErrorBase } from '../Errors.js';

function dateToSeconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}
function dateFromSeconds(seconds: number): Date {
  return new Date(seconds * 1000);
}

/** A single use bearer token sent by the client to the donation endpoint. */
export class DonationPermit extends ByteArray {
  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.DonationPermit_CheckValidContents);
  }
  /**
   * @throws {LibSignalErrorBase} (with a generic error code) if the verification failed
   */
  verify(keyPair: DonationPermitDerivedKeyPair, now: Date = new Date()): void {
    Native.DonationPermit_Verify(
      this.contents,
      dateToSeconds(now),
      keyPair.contents
    );
  }
  getSpendId(): Uint8Array<ArrayBuffer> {
    return Native.DonationPermit_SpendId(this.contents);
  }
}

export class DonationPermitDerivedKeyPair extends ByteArray {
  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.DonationPermitDerivedKeyPair_CheckValidContents);
  }
  static forExpiration(
    expiration: Date,
    params: ServerSecretParams
  ): DonationPermitDerivedKeyPair {
    return new DonationPermitDerivedKeyPair(
      Native.DonationPermitDerivedKeyPair_ForExpiration(
        dateToSeconds(expiration),
        params
      )
    );
  }
}

/** The blinded request sent from the client to the issuing server over the authenticated channel. */
export class DonationPermitRequest extends ByteArray {
  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.DonationPermitRequest_CheckValidContents);
  }
  issue(keyPair: DonationPermitDerivedKeyPair): DonationPermitResponse {
    const seed = randomBytes(RANDOM_LENGTH);
    return new DonationPermitResponse(
      Native.DonationPermitResponse_IssueDeterministic(
        this.contents,
        keyPair.serialize(),
        seed
      )
    );
  }
}

/**
 * Client local state used while obtaining permits.
 *
 * The context contains nonces and blinding scalars. Keep it only until the
 * issuing server responds. It is needed to unblind the response. Store the
 * permits, not this context.
 */
export class DonationPermitRequestContext extends ByteArray {
  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.DonationPermitRequestContext_CheckValidContents);
  }

  /**
   * Produces the blinded request to send to the issuing server over the authenticated channel.
   */
  request(): DonationPermitRequest {
    return new DonationPermitRequest(
      Native.DonationPermitRequestContext_Request(this.contents)
    );
  }

  /**
   * Verifies the issuing server's response against the pinned root public key,
   * checks the expiration window, and unblinds one permit per requested nonce.
   *
   * @throws {LibSignalErrorBase} (with a generic error code) if the verification failed
   */
  receive(
    response: DonationPermitResponse,
    publicParams: ServerPublicParams,
    now: Date
  ): DonationPermit[] {
    return Native.DonationPermitRequestContext_Receive(
      this.contents,
      response.serialize(),
      publicParams,
      dateToSeconds(now)
    ).map((bytes) => new DonationPermit(bytes));
  }

  /**
   * Creates a client request context for `count` permits.
   */
  static forCount(count: number): DonationPermitRequestContext {
    if ((count | 0) !== count || count <= 0) {
      throw new RangeError('invalid permit count');
    }
    const rngBytes = randomBytes(RANDOM_LENGTH);
    return new DonationPermitRequestContext(
      Native.DonationPermitRequestContext_NewDeterministic(count, rngBytes)
    );
  }
}

/** The issuing server's response to a donation permit request. */
export class DonationPermitResponse extends ByteArray {
  /** The shared expiration for the permits in this response. */
  expiration: Date;
  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.DonationPermitResponse_CheckValidContents);
    this.expiration = dateFromSeconds(
      Native.DonationPermitResponse_GetExpiration(this.contents)
    );
  }
  static defaultExpiration(now: Date = new Date()): Date {
    return dateFromSeconds(
      Native.DonationPermitResponse_DefaultExpiration(dateToSeconds(now))
    );
  }
}
