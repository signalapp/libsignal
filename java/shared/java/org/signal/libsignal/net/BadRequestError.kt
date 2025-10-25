//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// This file exists so that BadRequestError and its sub-interfaces can be applied to exception types
// shared between the client and server, even though typed request APIs are a client-only thing.

package org.signal.libsignal.net

/**
 * Marker interface for business logic errors returned by typed request APIs.
 *
 * All API-specific error types must implement this interface. Errors can
 * implement multiple specific error interfaces to indicate they may be
 * returned by multiple APIs.
 *
 * Example:
 * ```kotlin
 * sealed interface AciByUsernameFetchError : BadRequestError
 * object UserNotFound : AciByUsernameFetchError
 * ```
 */
public interface BadRequestError

/**
 * [org.signal.libsignal.usernames.UsernameLinkInvalidEntropyDataLength] and
 * [org.signal.libsignal.usernames.UsernameLinkInvalidLinkData]
 */
public sealed interface LookUpUsernameLinkFailure : BadRequestError
