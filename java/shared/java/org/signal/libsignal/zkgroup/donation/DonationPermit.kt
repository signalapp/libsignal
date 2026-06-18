//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.donation

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.filterAllExceptions
import org.signal.libsignal.internal.filterExceptions
import org.signal.libsignal.zkgroup.InvalidInputException
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.ServerSecretParams
import org.signal.libsignal.zkgroup.VerificationFailedException
import org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH
import java.security.SecureRandom
import java.time.Instant
import kotlin.jvm.Throws

/** A single use bearer token sent by the client to the donation endpoint. */
public class DonationPermit : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermit_CheckValidContents(contents)
    }
  }

  /**
   * Verifies this permit under the matching key pair.
   *
   * This also checks the permit's expiration window. It does not prevent reuse. The consuming server
   * must separately record spent IDs.
   */
  @Throws(VerificationFailedException::class)
  @JvmOverloads
  public fun verify(
    keyPair: DonationPermitDerivedKeyPair,
    now: Instant = Instant.now(),
  ) {
    filterExceptions<VerificationFailedException, _> {
      Native.DonationPermit_Verify(contents, now.epochSecond, keyPair.internalContentsForJNI)
    }
  }

  /** The expiration embedded in this permit. The consuming server uses it to select the key. */
  public val expiration: Instant by lazy {
    filterAllExceptions {
      Instant.ofEpochSecond(Native.DonationPermit_Expiration(contents))
    }
  }

  /**
   * The spend ID for this permit.
   *
   * The consuming server should scope spent ID storage to this permit's expiration.
   */
  public val spendId: ByteArray by lazy {
    filterAllExceptions {
      Native.DonationPermit_SpendId(contents)
    }
  }
}

/**
 * A key pair derived from the server's root secret for a permit expiration.
 *
 * The same derived key pair issues permits and verifies them.
 */
public class DonationPermitDerivedKeyPair : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitDerivedKeyPair_CheckValidContents(contents)
    }
  }

  public companion object {
    /**
     * Derives the key pair for a permit expiration from the server root secret.
     */
    @JvmStatic
    public fun forExpiration(
      expiration: Instant,
      params: ServerSecretParams,
    ): DonationPermitDerivedKeyPair =
      filterAllExceptions {
        DonationPermitDerivedKeyPair(Native.DonationPermitDerivedKeyPair_ForExpiration(expiration.epochSecond, params))
      }
  }
}

/** The blinded request sent from the client to the issuing server over the authenticated channel. */
public class DonationPermitRequest : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitRequest_CheckValidContents(contents)
    }
  }

  /**
   * The number of blinded points in the request.
   *
   * The issuing server can use this to cap the batch size before issuing permits.
   */
  public val permitCount: Int by lazy {
    filterAllExceptions {
      Native.DonationPermitRequest_Len(contents)
    }
  }

  /**
   * Issues permits for this request.
   *
   * This blindly signs every point in the request. The issuing server is responsible for policy
   * checks before calling this.
   */
  @JvmOverloads
  public fun issue(
    keyPair: DonationPermitDerivedKeyPair,
    rng: SecureRandom = SecureRandom(),
  ): DonationPermitResponse {
    val seed = ByteArray(RANDOM_LENGTH)
    rng.nextBytes(seed)
    return DonationPermitResponse(
      Native.DonationPermitResponse_IssueDeterministic(
        contents,
        keyPair.internalContentsForJNI,
        seed,
      ),
    )
  }
}

/**
 * Client local state used while obtaining permits.
 *
 * The context contains nonces and blinding scalars. Keep it only until the issuing server responds.
 * It is needed to unblind the response. Store the permits, not this context.
 */
public class DonationPermitRequestContext : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitRequestContext_CheckValidContents(contents)
    }
  }

  /**
   * Produces the blinded request to send to the issuing server over the authenticated channel.
   */
  public fun request(): DonationPermitRequest =
    filterAllExceptions { DonationPermitRequest(Native.DonationPermitRequestContext_Request(contents)) }

  /**
   * Verifies the issuing server's response against the pinned root public key.
   *
   * This checks the expiration window and unblinds one permit per requested nonce.
   */
  @Throws(VerificationFailedException::class)
  @JvmOverloads
  public fun receive(
    response: DonationPermitResponse,
    publicParams: ServerPublicParams,
    now: Instant = Instant.now(),
  ): List<DonationPermit> =
    filterExceptions<VerificationFailedException, _> {
      // Allow use of java.lang.Object
      @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
      Native
        .DonationPermitRequestContext_Receive(
          contents,
          response.internalContentsForJNI,
          publicParams,
          now.epochSecond,
        ).asList()
        .map {
          DonationPermit(it as ByteArray)
        }
    }

  public companion object {
    /**
     * Creates a client request context for a given permit count.
     *
     * @param count must be > 0
     */
    @JvmStatic
    @JvmOverloads
    public fun forCount(
      count: Int,
      rng: SecureRandom = SecureRandom(),
    ): DonationPermitRequestContext =
      try {
        require(count > 0)
        val rngBytes = ByteArray(RANDOM_LENGTH)
        rng.nextBytes(rngBytes)
        DonationPermitRequestContext(Native.DonationPermitRequestContext_NewDeterministic(count, rngBytes))
      } catch (e: InvalidInputException) {
        throw AssertionError(e)
      }
  }
}

/** The issuing server's response to a donation permit request. */
public class DonationPermitResponse : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitResponse_CheckValidContents(contents)
    }
  }

  /** The shared expiration for the permits in this response. */
  public val expiration: Instant by lazy {
    Instant.ofEpochSecond(
      Native.DonationPermitResponse_GetExpiration(contents),
    )
  }

  public companion object {
    /**
     * Returns the default day aligned expiration for a response created at [currentTime].
     */
    @JvmOverloads
    @JvmStatic
    public fun defaultExpiration(currentTime: Instant = Instant.now()): Instant =
      Instant.ofEpochSecond(Native.DonationPermitResponse_DefaultExpiration(currentTime.epochSecond))
  }
}
