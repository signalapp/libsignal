//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import * as Native from '../Native.js';
import ByteArray from './internal/ByteArray.js';
import { RANDOM_LENGTH } from './internal/Constants.js';
import type {
  ZkCredentialKeyPair,
  ZkCredentialPublicKey,
} from './ZkCredentialKey.js';
import type { Aci } from '../Address.js';
import type GenericServerPublicParams from './GenericServerPublicParams.js';
import type GenericServerSecretParams from './GenericServerSecretParams.js';
import type { LibSignalError } from '../Errors.js';

/**
 * Client-side state for an in-flight avatar upload credential request.
 *
 * This value is not sent over the wire; it is retained by the client between issuing a {@link
 * AvatarUploadCredentialRequest} and receiving the corresponding {@link
 * AvatarUploadCredentialResponse}.
 */
export class AvatarUploadCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(
      contents,
      Native.AvatarUploadCredentialRequestContext_CheckValidContents
    );
  }

  /**
   * Creates a new request context for `aci`.
   *
   * @param aci The account the credential will be issued for. The issuing server must independently
   * authenticate this ACI.
   * @param zkCredentialKeyPair The account's long-term Ristretto ZK credential key pair.
   * @param rotationId The server-chosen avatar slot rotation ID, which the client already received
   * when it set its ZK credential key. It is folded into the commitment; the issuing server
   * verifies the request against its own rotation ID, so this must match the server's value.
   */
  static create(
    aci: Aci,
    zkCredentialKeyPair: ZkCredentialKeyPair,
    rotationId: bigint
  ): AvatarUploadCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);
    return this.createWithRandom(aci, zkCredentialKeyPair, rotationId, random);
  }

  /**
   * Creates a new request context, using a dedicated source of randomness.
   *
   * This can be used to make tests deterministic. Prefer {@link #create}
   * if the source of randomness doesn't matter.
   */
  static createWithRandom(
    aci: Aci,
    zkCredentialKeyPair: ZkCredentialKeyPair,
    rotationId: bigint,
    random: Uint8Array<ArrayBuffer>
  ): AvatarUploadCredentialRequestContext {
    const newContents = Native.AvatarUploadCredentialRequestContext_New(
      aci.getServiceIdFixedWidthBinary(),
      zkCredentialKeyPair.getContents(),
      rotationId,
      random
    );
    return new AvatarUploadCredentialRequestContext(newContents);
  }

  /** The request to send to the issuing server. */
  getRequest(): AvatarUploadCredentialRequest {
    const newContents = Native.AvatarUploadCredentialRequestContext_GetRequest(
      this.contents
    );
    return new AvatarUploadCredentialRequest(newContents);
  }

  /**
   * Verifies the issuing server's response and produces a usable {@link AvatarUploadCredential}.
   *
   * The issuing server chooses the redemption time and embeds it in `response`. The client
   * doesn't need to predict it; this call confirms only that the credential is usable at
   * `now`, since the verifying server applies the same window (see
   * {@link AvatarUploadCredentialPresentation#verify}).
   *
   * @param response The response received from the issuing server.
   * @param params The public params matching the secret params the issuing server used.
   * @param now The client's view of wall-clock time. The response's redemption time must be
   * day-aligned and within the redemption window relative to this.
   * @throws {LibSignalError} if the response is not valid for this context.
   */
  receiveResponse(
    response: AvatarUploadCredentialResponse,
    params: GenericServerPublicParams,
    now: Date = new Date()
  ): AvatarUploadCredential {
    const newContents =
      Native.AvatarUploadCredentialRequestContext_ReceiveResponse(
        this.getContents(),
        response.getContents(),
        Math.floor(now.getTime() / 1000),
        params.getContents()
      );
    return new AvatarUploadCredential(newContents);
  }
}

/** The request a client sends to the issuing server to obtain an avatar upload credential. */
export class AvatarUploadCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.AvatarUploadCredentialRequest_CheckValidContents);
  }

  /**
   * Issues an avatar upload credential.
   *
   * @param aci The account this credential is for. The server must independently authenticate the
   * client as this ACI.
   * @param zkCredentialKeyPublic The account's long-term Ristretto ZK credential public key from
   * the server's authoritative store for this account. The request's well-formedness proof
   * binds the blinded commitment to this key, so passing the wrong value will fail issuance.
   * @param rotationId The server-chosen avatar slot rotation ID, incorporated into the commitment.
   * The client received this value when it set its ZK credential key.
   * @param redemptionTime Must be a round number of days.
   * @param params The params that will be used by the verifying server to verify this credential.
   * @throws {LibSignalError} if the request is not well-formed for `aci` and
   * `zkCredentialKeyPublic`.
   */
  issueCredential(
    aci: Aci,
    zkCredentialKeyPublic: ZkCredentialPublicKey,
    rotationId: bigint,
    redemptionTime: Date,
    params: GenericServerSecretParams
  ): AvatarUploadCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(
      aci,
      zkCredentialKeyPublic,
      rotationId,
      redemptionTime,
      params,
      random
    );
  }

  /**
   * Issues an avatar upload credential, using a dedicated source of randomness.
   *
   * This can be used to make tests deterministic. Prefer {@link #issueCredential}
   * if the source of randomness doesn't matter.
   */
  issueCredentialWithRandom(
    aci: Aci,
    zkCredentialKeyPublic: ZkCredentialPublicKey,
    rotationId: bigint,
    redemptionTime: Date,
    params: GenericServerSecretParams,
    random: Uint8Array<ArrayBuffer>
  ): AvatarUploadCredentialResponse {
    const newContents = Native.AvatarUploadCredentialRequest_IssueDeterministic(
      this.getContents(),
      aci.getServiceIdFixedWidthBinary(),
      zkCredentialKeyPublic.getContents(),
      rotationId,
      Math.floor(redemptionTime.getTime() / 1000),
      params.getContents(),
      random
    );
    return new AvatarUploadCredentialResponse(newContents);
  }
}

/** The issuing server's response to an {@link AvatarUploadCredentialRequest}. */
export class AvatarUploadCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.AvatarUploadCredentialResponse_CheckValidContents);
  }
}

/**
 * A usable avatar upload credential, held by the client after a successful issuance.
 *
 * Call {@link #present} to produce an {@link AvatarUploadCredentialPresentation} for a verifying
 * server.
 */
export class AvatarUploadCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.AvatarUploadCredential_CheckValidContents);
  }

  /** Produces a presentation of this credential for a verifying server. */
  present(
    serverParams: GenericServerPublicParams
  ): AvatarUploadCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(serverParams, random);
  }

  /**
   * Produces a presentation of this credential, using a dedicated source of randomness.
   *
   * This can be used to make tests deterministic. Prefer {@link #present}
   * if the source of randomness doesn't matter.
   */
  presentWithRandom(
    serverParams: GenericServerPublicParams,
    random: Uint8Array<ArrayBuffer>
  ): AvatarUploadCredentialPresentation {
    const newContents = Native.AvatarUploadCredential_PresentDeterministic(
      this.getContents(),
      serverParams.getContents(),
      random
    );

    return new AvatarUploadCredentialPresentation(newContents);
  }

  /**
   * The 32-byte commitment `Cm` (the avatar slot identifier).
   *
   * This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
   */
  getCommitment(): Uint8Array<ArrayBuffer> {
    return Native.AvatarUploadCredential_GetCm(this.contents);
  }

  /** The redemption time the issuing server chose for this credential. */
  getRedemptionTime(): Date {
    return new Date(
      1000 * Native.AvatarUploadCredential_GetRedemptionTime(this.contents)
    );
  }
}

/** A presentation of an {@link AvatarUploadCredential}, sent to a verifying server. */
export class AvatarUploadCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(
      contents,
      Native.AvatarUploadCredentialPresentation_CheckValidContents
    );
  }

  /**
   * Verifies the presentation against `now`.
   *
   * @throws {LibSignalError} if the presentation is invalid or outside its redemption window.
   */
  verify(
    serverParams: GenericServerSecretParams,
    now: Date = new Date()
  ): void {
    Native.AvatarUploadCredentialPresentation_Verify(
      this.getContents(),
      Math.floor(now.getTime() / 1000),
      serverParams.getContents()
    );
  }

  /**
   * The 32-byte commitment `Cm` (the avatar slot identifier) revealed by this presentation.
   *
   * This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
   */
  getCommitment(): Uint8Array<ArrayBuffer> {
    return Native.AvatarUploadCredentialPresentation_GetCm(this.contents);
  }

  /** The redemption time the credential was issued for. */
  getRedemptionTime(): Date {
    return new Date(
      1000 *
        Native.AvatarUploadCredentialPresentation_GetRedemptionTime(
          this.contents
        )
    );
  }
}
