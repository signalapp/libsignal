//
//  Copyright (c) 2019 Open Whisper Systems. All rights reserved.
//

import Foundation
import SignalFfi

public class Native {
  static let FFI_RETURN_OK             = 0;
  static let FFI_RETURN_INTERNAL_ERROR = 1; // ZkGroupError
  static let FFI_RETURN_INPUT_ERROR    = 2;
  static let RANDOM_LENGTH = 32;
}
