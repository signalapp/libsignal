//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

extension StoreContext {
    internal func withOpaquePointer<Result>(_ body: (UnsafeMutablePointer<StoreContext>) throws -> Result) rethrows -> Result {
        var selfAsPointer: StoreContext = self
        return try withUnsafeMutablePointer(to: &selfAsPointer, body)
    }
}

internal func withIdentityKeyStore<Result>(_ store: IdentityKeyStore, _ body: (UnsafePointer<SignalIdentityKeyStore>) throws -> Result) throws -> Result {
    func ffiShimGetIdentityKeyPair(store_ctx: UnsafeMutableRawPointer?,
                                   keyp: UnsafeMutablePointer<OpaquePointer?>?,
                                   ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<IdentityKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var privateKey = try store.identityKeyPair(context: context).privateKey
            keyp!.pointee = try cloneOrTakeHandle(from: &privateKey)
            return 0
        }
    }

    func ffiShimGetLocalRegistrationId(store_ctx: UnsafeMutableRawPointer?,
                                       idp: UnsafeMutablePointer<UInt32>?,
                                       ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<IdentityKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            let id = try store.localRegistrationId(context: context)
            idp!.pointee = id
            return 0
        }
    }

    func ffiShimSaveIdentity(store_ctx: UnsafeMutableRawPointer?,
                             address: OpaquePointer?,
                             public_key: OpaquePointer?,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<IdentityKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            var public_key = PublicKey(borrowing: public_key)
            defer { cloneOrForgetAsNeeded(&public_key) }
            let identity = IdentityKey(publicKey: public_key)
            let new_id = try store.saveIdentity(identity, for: address, context: context)
            if new_id {
                return 1
            } else {
                return 0
            }
        }
    }

    func ffiShimGetIdentity(store_ctx: UnsafeMutableRawPointer?,
                            public_key: UnsafeMutablePointer<OpaquePointer?>?,
                            address: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<IdentityKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            if let pk = try store.identity(for: address, context: context) {
                var publicKey = pk.publicKey
                public_key!.pointee = try cloneOrTakeHandle(from: &publicKey)
            } else {
                public_key!.pointee = nil
            }
            return 0
        }
    }

    func ffiShimIsTrustedIdentity(store_ctx: UnsafeMutableRawPointer?,
                                  address: OpaquePointer?,
                                  public_key: OpaquePointer?,
                                  raw_direction: UInt32,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<IdentityKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            var public_key = PublicKey(borrowing: public_key)
            defer { cloneOrForgetAsNeeded(&public_key) }
            let direction: Direction
            switch SignalDirection(raw_direction) {
            case SignalDirectionSending:
                direction = .sending
            case SignalDirectionReceiving:
                direction = .receiving
            default:
                assertionFailure("unexpected direction value")
                return -1
            }
            let identity = IdentityKey(publicKey: public_key)
            let trusted = try store.isTrustedIdentity(identity, for: address, direction: direction, context: context)
            return trusted ? 1 : 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalIdentityKeyStore(
            ctx: $0,
            get_identity_key_pair: ffiShimGetIdentityKeyPair,
            get_local_registration_id: ffiShimGetLocalRegistrationId,
            save_identity: ffiShimSaveIdentity,
            get_identity: ffiShimGetIdentity,
            is_trusted_identity: ffiShimIsTrustedIdentity)
        return try body(&ffiStore)
    }
}

internal func withPreKeyStore<Result>(_ store: PreKeyStore, _ body: (UnsafePointer<SignalPreKeyStore>) throws -> Result) throws -> Result {
    func ffiShimStorePreKey(store_ctx: UnsafeMutableRawPointer?,
                            id: UInt32,
                            record: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<PreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = PreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storePreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadPreKey(store_ctx: UnsafeMutableRawPointer?,
                           recordp: UnsafeMutablePointer<OpaquePointer?>?,
                           id: UInt32,
                           ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<PreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = try store.loadPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    func ffiShimRemovePreKey(store_ctx: UnsafeMutableRawPointer?,
                             id: UInt32,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<PreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            try store.removePreKey(id: id, context: context)
            return 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalPreKeyStore(
            ctx: $0,
            load_pre_key: ffiShimLoadPreKey,
            store_pre_key: ffiShimStorePreKey,
            remove_pre_key: ffiShimRemovePreKey)
        return try body(&ffiStore)
    }
}

internal func withSignedPreKeyStore<Result>(_ store: SignedPreKeyStore, _ body: (UnsafePointer<SignalSignedPreKeyStore>) throws -> Result) throws -> Result {
    func ffiShimStoreSignedPreKey(store_ctx: UnsafeMutableRawPointer?,
                                  id: UInt32,
                                  record: OpaquePointer?,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignedPreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = SignedPreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSignedPreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadSignedPreKey(store_ctx: UnsafeMutableRawPointer?,
                                 recordp: UnsafeMutablePointer<OpaquePointer?>?,
                                 id: UInt32,
                                 ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignedPreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = try store.loadSignedPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalSignedPreKeyStore(
            ctx: $0,
            load_signed_pre_key: ffiShimLoadSignedPreKey,
            store_signed_pre_key: ffiShimStoreSignedPreKey)
        return try body(&ffiStore)
    }
}

internal func withKyberPreKeyStore<Result>(_ store: KyberPreKeyStore, _ body: (UnsafePointer<SignalKyberPreKeyStore>) throws -> Result) throws -> Result {
    func ffiShimStoreKyberPreKey(store_ctx: UnsafeMutableRawPointer?,
                                 id: UInt32,
                                 record: OpaquePointer?,
                                 ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<KyberPreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = KyberPreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeKyberPreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadKyberPreKey(store_ctx: UnsafeMutableRawPointer?,
                                recordp: UnsafeMutablePointer<OpaquePointer?>?,
                                id: UInt32,
                                ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<KyberPreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var record = try store.loadKyberPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    func ffiShimMarkKyberPreKeyUsed(store_ctx: UnsafeMutableRawPointer?,
                                    id: UInt32,
                                    ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<KyberPreKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            try store.markKyberPreKeyUsed(id: id, context: context)
            return 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalKyberPreKeyStore(
            ctx: $0,
            load_kyber_pre_key: ffiShimLoadKyberPreKey,
            store_kyber_pre_key: ffiShimStoreKyberPreKey,
            mark_kyber_pre_key_used: ffiShimMarkKyberPreKeyUsed)
        return try body(&ffiStore)
    }
}

internal func withSessionStore<Result>(_ store: SessionStore, _ body: (UnsafePointer<SignalSessionStore>) throws -> Result) throws -> Result {
    func ffiShimStoreSession(store_ctx: UnsafeMutableRawPointer?,
                             address: OpaquePointer?,
                             record: OpaquePointer?,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SessionStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            var record = SessionRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSession(record, for: address, context: context)
            return 0
        }
    }

    func ffiShimLoadSession(store_ctx: UnsafeMutableRawPointer?,
                            recordp: UnsafeMutablePointer<OpaquePointer?>?,
                            address: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SessionStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            if var record = try store.loadSession(for: address, context: context) {
                recordp!.pointee = try cloneOrTakeHandle(from: &record)
            } else {
                recordp!.pointee = nil
            }
            return 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalSessionStore(
            ctx: $0,
            load_session: ffiShimLoadSession,
            store_session: ffiShimStoreSession)
        return try body(&ffiStore)
    }
}

internal func withSenderKeyStore<Result>(_ store: SenderKeyStore, _ body: (UnsafePointer<SignalSenderKeyStore>) throws -> Result) rethrows -> Result {
    func ffiShimStoreSenderKey(store_ctx: UnsafeMutableRawPointer?,
                               sender: OpaquePointer?,
                               distributionId: UnsafePointer<uuid_t>?,
                               record: OpaquePointer?,
                               ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SenderKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var sender = ProtocolAddress(borrowing: sender)
            let distributionId = UUID(uuid: distributionId!.pointee)
            defer { cloneOrForgetAsNeeded(&sender) }
            var record = SenderKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSenderKey(from: sender, distributionId: distributionId, record: record, context: context)
            return 0
        }
    }

    func ffiShimLoadSenderKey(store_ctx: UnsafeMutableRawPointer?,
                              recordp: UnsafeMutablePointer<OpaquePointer?>?,
                              sender: OpaquePointer?,
                              distributionId: UnsafePointer<uuid_t>?,
                              ctx: UnsafeMutableRawPointer?) -> Int32 {
        let storeContext = store_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SenderKeyStore>.self)
        return storeContext.pointee.catchCallbackErrors { store in
            let context = ctx!.assumingMemoryBound(to: StoreContext.self).pointee
            var sender = ProtocolAddress(borrowing: sender)
            let distributionId = UUID(uuid: distributionId!.pointee)
            defer { cloneOrForgetAsNeeded(&sender) }
            if var record = try store.loadSenderKey(from: sender, distributionId: distributionId, context: context) {
                recordp!.pointee = try cloneOrTakeHandle(from: &record)
            } else {
                recordp!.pointee = nil
            }
            return 0
        }
    }

    return try rethrowCallbackErrors(store) {
        var ffiStore = SignalSenderKeyStore(
            ctx: $0,
            load_sender_key: ffiShimLoadSenderKey,
            store_sender_key: ffiShimStoreSenderKey)
        return try body(&ffiStore)
    }
}
