//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol

/**
 * The type used in memory to represent a *device*, i.e. a particular Signal client instance which
 * represents some user.
 *
 * It must be in the range of `1..=127`
 */
public typealias DeviceId = Int
