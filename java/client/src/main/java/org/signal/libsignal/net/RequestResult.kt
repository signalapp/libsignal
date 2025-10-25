//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import java.io.IOException
import java.time.Duration

/**
 * High-level result type for chat server requests.
 *
 * This sealed interface represents all possible outcomes from network requests:
 * - [Success]: The request completed successfully with a result
 * - [NonSuccess]: The request reached the server but returned a business logic error
 * - [RetryableNetworkError]: A network failure occurred; the request may succeed if retried
 * - [ApplicationError]: A client-side bug prevented request completion
 *
 * @param T The type of successful result data
 * @param E The type of error that occurred. If a particular API has no possible errors,
 *          we use [Nothing] instead.
 */
public sealed interface RequestResult<out T, out E : BadRequestError> {
  /**
   * The request completed successfully and produced a result.
   *
   * @property result The data returned by the successful request. May be nullable
   *                  for APIs where absence of data is a valid response.
   */
  public data class Success<T>(
    val result: T,
  ) : RequestResult<T, Nothing>

  /**
   * We successfully made the request, but the server returned an error.
   *
   * This represents expected error conditions defined by the API, such as
   * "invalid authorization" or "outdated recipient information". These errors are part of the
   * API contract and should be handled explicitly by callers.
   *
   * @property error The specific error that occurred
   */
  public data class NonSuccess<E : BadRequestError>(
    val error: E,
  ) : RequestResult<Nothing, E>

  /**
   * A retryable network failure occurred before receiving a response.
   *
   * This includes connection failures, timeouts, server errors, and
   * rate limiting. Callers may retry these requests, optionally after a delay.
   *
   * Possible types for [networkError] include but are not limited to:
   * - [TimeoutException]: occurs when the request takes too long to complete.
   * - [ConnectedElsewhereException]: occurs when a client connects elsewhere with
   *   same credentials before the request could complete
   * - [ConnectionInvalidatedException]: occurs when the connection to the server is
   *   invalidated (e.g. the account is deleted) before the request could complete
   * - [RetryLaterException]: occurs when the client hits a rate limit, and must wait at least
   *   the duration specified before retrying. [retryAfter] will always be set with this error
   * - [TransportFailureException]: occurs when the transport layer fails
   * - [ServerSideErrorException]: occurs when the server returns a response
   *   indicating a server-side error occurred. You may wish to retry with an especially
   *   long timeout on critical paths, like message sending, to avoid worsening a server
   *   outage.
   *
   * @property networkError The underlying I/O error that caused the failure
   * @property retryAfter Optional advisory duration to wait before retrying.
   *                    If present, the client should not retry before this duration
   *                    elapses, but may choose to wait longer.
   */
  public data class RetryableNetworkError(
    val networkError: IOException,
    val retryAfter: Duration? = null,
  ) : RequestResult<Nothing, Nothing>

  /**
   * A client-side issue prevented the request from completing.
   *
   * This likely indicates a bug in libsignal.
   *
   * Possible types for [cause] include but are not limited to:
   * - [UnexpectedResponseException]: occurs when we are unable to parse the response
   *
   * @property cause The exception that indicates the bug. May contain stack
   *                 traces and other diagnostic information.
   */
  public data class ApplicationError(
    val cause: Throwable,
  ) : RequestResult<Nothing, Nothing>

  public fun <R> map(transform: (T) -> R): RequestResult<R, E> =
    when (this) {
      is Success -> Success(transform(result))
      is NonSuccess -> this
      is RetryableNetworkError -> this
      is ApplicationError -> this
    }
}

@JvmName("toRequestResultTyped")
internal inline fun <reified E : BadRequestError> Throwable.toRequestResult(): RequestResult<Nothing, E> =
  when (this) {
    is E -> RequestResult.NonSuccess(this)
    else -> this.toRequestResult() as RequestResult<Nothing, Nothing>
  }

internal fun Throwable.toRequestResult(): RequestResult<Nothing, Nothing> =
  when (this) {
    is TimeoutException -> RequestResult.RetryableNetworkError(this, null)
    is ConnectedElsewhereException -> RequestResult.RetryableNetworkError(this)
    // ConnectionInvalidated is mapped to a network error. Only one legacy API uses its
    // specific meaning; all other APIs treat it as a generic network error.
    is ConnectionInvalidatedException -> RequestResult.RetryableNetworkError(this)
    is RetryLaterException -> RequestResult.RetryableNetworkError(this, duration)
    is TransportFailureException -> RequestResult.RetryableNetworkError(this)
    is ServerSideErrorException -> RequestResult.RetryableNetworkError(this)
    is UnexpectedResponseException -> RequestResult.ApplicationError(this)
    else -> RequestResult.ApplicationError(this)
  }

/**
 * Safely unwraps a [CompletableFuture]<[RequestResult]> to a [RequestResult].
 *
 * This extension function handles the case where the Future itself fails
 * (as opposed to the request returning an error result). Any exceptions
 * thrown while waiting for the Future are converted to [ApplicationError].
 *
 * @return The [RequestResult] from the Future, or [ApplicationError] if the
 *         Future failed to complete normally
 */
public fun <T, E : BadRequestError> CompletableFuture<RequestResult<T, E>>.getOrError(): RequestResult<T, E> =
  try {
    this.get()
  } catch (e: Throwable) {
    RequestResult.ApplicationError(e)
  }
