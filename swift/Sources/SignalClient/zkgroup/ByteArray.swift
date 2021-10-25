//
//  Copyright (c) 2019 Open Whisper Systems. All rights reserved.
//

import Foundation
import SignalFfi

public class ByteArray {
    let contents: [UInt8]

    init(newContents: [UInt8], expectedLength: Int, unrecoverable: Bool = false) throws {
        if newContents.count != expectedLength {
            throw ZkGroupException.IllegalArgument
        }
        contents = newContents
    }

  func getInternalContentsForFFI() -> [UInt8] {
    return contents
  }

    
}
