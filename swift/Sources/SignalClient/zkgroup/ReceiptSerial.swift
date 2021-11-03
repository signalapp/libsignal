//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

public class ReceiptSerial: ByteArray {

  public static let SIZE: Int = 16

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ReceiptSerial.SIZE)
  }

}
