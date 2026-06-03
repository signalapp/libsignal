//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/** Exposes kotlinx.serialization's JSON support for JsonElement to Java. */
internal fun decodeJson(jsonString: String): JsonElement = Json.decodeFromString(jsonString)
