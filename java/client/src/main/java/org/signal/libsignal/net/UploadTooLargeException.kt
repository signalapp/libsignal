/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The request size was larger than the maximum supported upload size
 *
 * See the specific request docs for more information.
 */
public class UploadTooLargeException :
  IOException,
  BadRequestError,
  GetUploadFormError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
