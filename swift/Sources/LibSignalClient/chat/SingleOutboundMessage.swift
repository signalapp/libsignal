//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A message to send to a single device of a peer.
///
/// Used by APIs like ``UnauthMessagesService/sendMessage(to:timestamp:contents:auth:onlineOnly:urgent:)``
public struct SingleOutboundMessage<Contents> {
    public var deviceId: DeviceId
    public var registrationId: UInt32
    public var contents: Contents

    public init(deviceId: DeviceId, registrationId: UInt32, contents: Contents) {
        self.deviceId = deviceId
        self.registrationId = registrationId
        self.contents = contents
    }
}

public typealias SingleOutboundSealedSenderMessage = SingleOutboundMessage<Data>
