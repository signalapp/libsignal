//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

// Generated by zkgroup/codegen/codegen.py - do not edit

package org.signal.zkgroup.groups;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.ZkGroupError;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.zkgroup.internal.Native;

public final class GroupPublicParams extends ByteArray {

  public static final int SIZE = 97;

  public GroupPublicParams(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    
    int ffi_return = Native.groupPublicParamsCheckValidContentsJNI(contents);

    if (ffi_return == Native.FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException("FFI_RETURN_INPUT_ERROR");
    }

    if (ffi_return != Native.FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }
  }

  public GroupIdentifier getGroupIdentifier() {
    byte[] newContents = new byte[GroupIdentifier.SIZE];

    int ffi_return = Native.groupPublicParamsGetGroupIdentifierJNI(contents, newContents);

    if (ffi_return != Native.FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    try {
      return new GroupIdentifier(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }

  }

  public byte[] serialize() {
    return contents.clone();
  }

}
