//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum UserBasedAuthorization: Sendable {
    case accessKey(Data)
    case groupSend(GroupSendFullToken)
}

public enum DeviceSpecifier: Sendable {
    case allDevices
    case specificDevice(DeviceId)
}

public protocol UnauthKeysService: Sendable {
    /// Fetch the prekeys for a given target user
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if ``auth`` is not valid for the target
    ///   - ``SignalError/serviceIdNotFound(_:)`` if requested identity or device does not
    ///     exist, or device has no available prekeys.
    ///   - the standard Signal network errors
    func getPreKeys(
        for target: ServiceId,
        device: DeviceSpecifier,
        auth: UserBasedAuthorization,
    ) async throws -> (
        IdentityKey,
        [PreKeyBundle]
    )
}

extension UnauthenticatedChatConnection: UnauthKeysService {
    public func getPreKeys(
        for target: ServiceId,
        device: DeviceSpecifier,
        auth: UserBasedAuthorization,
    ) async throws -> (
        IdentityKey,
        [PreKeyBundle]
    ) {
        let device =
            switch device {
            case .allDevices: Int32(-1)
            case .specificDevice(let id): Int32(id.rawValue)
            }
        let out: SignalFfiPreKeysResponse
        switch auth {
        case .accessKey(let auth):
            let authBytes = try ByteArray(newContents: auth, expectedLength: 16)
            out = try await self.tokioAsyncContext.invokeAsyncFunction {
                promise,
                tokioAsyncContext in
                withNativeHandle { chatService in
                    target.withPointerToFixedWidthBinary { target in
                        try! authBytes.withUnsafePointerToSerialized { authBytes in
                            signal_unauthenticated_chat_connection_get_pre_keys_access_key_auth(
                                promise,
                                tokioAsyncContext.const(),
                                chatService.const(),
                                authBytes,
                                target,
                                device,
                            )
                        }
                    }
                }
            }
        case .groupSend(let groupSendFullToken):
            out = try await self.tokioAsyncContext.invokeAsyncFunction {
                promise,
                tokioAsyncContext in
                withNativeHandle { chatService in
                    target.withPointerToFixedWidthBinary { target in
                        groupSendFullToken.withUnsafeBorrowedBuffer { auth in
                            signal_unauthenticated_chat_connection_get_pre_keys_access_group_auth(
                                promise,
                                tokioAsyncContext.const(),
                                chatService.const(),
                                auth,
                                target,
                                device,
                            )
                        }
                    }
                }
            }
        }
        let publicKey = PublicKey(owned: NonNull(out.identity_key)!)
        let identityKey = IdentityKey(publicKey: publicKey)
        let preKeysRaw = UnsafeBufferPointer(start: out.pre_key_bundles.base, count: out.pre_key_bundles.length)
        let preKeys = preKeysRaw.map { PreKeyBundle(owned: NonNull($0)!) }
        signal_free_outer_buffer_list_of_prekey_bundles(out.pre_key_bundles)
        return (identityKey, preKeys)
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthKeysService> {
    public static var keys: Self { .init() }
}
