/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.util

import org.signal.libsignal.protocol.logging.SignalProtocolLogger

public class TestLoggerDecorator(
  private val inner: SignalProtocolLogger,
) : SignalProtocolLogger {
  public data class LogRecord(
    val priority: Int,
    val tag: String,
    val message: String,
  )

  companion object {
    public val logs = ThreadLocal<MutableList<LogRecord>>()
  }

  override fun log(
    priority: Int,
    tag: String?,
    message: String?,
  ) {
    logs.get()?.add(LogRecord(priority, tag!!, message!!))
    inner.log(priority, tag, message)
  }
}
