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

public class DonationPermit : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermit_CheckValidContents(contents)
    }
  }

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
}

public class DonationPermitDerivedKeyPair : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitDerivedKeyPair_CheckValidContents(contents)
    }
  }

  public companion object {
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

public class DonationPermitRequest : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitRequest_CheckValidContents(contents)
    }
  }

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

public class DonationPermitRequestContext : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitRequestContext_CheckValidContents(contents)
    }
  }

  public fun request(): DonationPermitRequest =
    filterAllExceptions { DonationPermitRequest(Native.DonationPermitRequestContext_Request(contents)) }

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
     * Construct a [DonationPermitRequestContext] from a given permit count and secure random
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

public class DonationPermitResponse : org.signal.libsignal.zkgroup.internal.ByteArray {
  @Throws(InvalidInputException::class)
  public constructor(contents: ByteArray) : super(contents) {
    filterExceptions<InvalidInputException, _> {
      Native.DonationPermitResponse_CheckValidContents(contents)
    }
  }

  public val expiration: Instant by lazy {
    Instant.ofEpochSecond(
      Native.DonationPermitResponse_GetExpiration(contents),
    )
  }

  public companion object {
    @JvmOverloads
    @JvmStatic
    public fun defaultExpiration(currentTime: Instant = Instant.now()): Instant =
      Instant.ofEpochSecond(Native.DonationPermitResponse_DefaultExpiration(currentTime.epochSecond))
  }
}
