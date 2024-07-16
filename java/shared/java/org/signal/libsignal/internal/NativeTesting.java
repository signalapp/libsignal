//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.libsignal.internal;

import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.logging.Log;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Future;
import java.util.UUID;
import java.util.Map;

public final class NativeTesting {
  private static void loadNativeCode() {
    try {
      Native.loadLibrary("signal_jni_testing");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static {
    loadNativeCode();
  }

  private NativeTesting() {}

  public static native void ComparableBackup_Destroy(long handle);
  public static native String ComparableBackup_GetComparableString(long backup);
  public static native Object[] ComparableBackup_GetUnknownFields(long backup);
  public static native long ComparableBackup_ReadUnencrypted(InputStream stream, long len, int purpose) throws Exception;

  public static native int test_only_fn_returns_123();
}
