//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

internal func withIdentityKeyStore<Result>(_ store: IdentityKeyStore, _ context: StoreContext, _ body: (SignalConstPointerFfiIdentityKeyStoreStruct) throws -> Result) throws -> Result {
    func ffiShimGetIdentityKeyPair(
        storeCtx: UnsafeMutableRawPointer?,
        keyp: UnsafeMutablePointer<SignalMutPointerPrivateKey>?
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(IdentityKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var privateKey = try store.identityKeyPair(context: context).privateKey
            keyp!.pointee = try cloneOrTakeHandle(from: &privateKey)
            return 0
        }
    }

    func ffiShimGetLocalRegistrationId(
        storeCtx: UnsafeMutableRawPointer?,
        idp: UnsafeMutablePointer<UInt32>?
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(IdentityKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            let id = try store.localRegistrationId(context: context)
            idp!.pointee = id
            return 0
        }
    }

    func ffiShimSaveIdentity(
        storeCtx: UnsafeMutableRawPointer?,
        address: SignalConstPointerProtocolAddress,
        public_key: SignalConstPointerPublicKey
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(IdentityKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
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

    func ffiShimGetIdentity(
        storeCtx: UnsafeMutableRawPointer?,
        public_key: UnsafeMutablePointer<SignalMutPointerPublicKey>?,
        address: SignalConstPointerProtocolAddress
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(IdentityKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            if let pk = try store.identity(for: address, context: context) {
                var publicKey = pk.publicKey
                public_key!.pointee = try cloneOrTakeHandle(from: &publicKey)
            } else {
                public_key!.pointee = SignalMutPointerPublicKey()
            }
            return 0
        }
    }

    func ffiShimIsTrustedIdentity(
        storeCtx: UnsafeMutableRawPointer?,
        address: SignalConstPointerProtocolAddress,
        public_key: SignalConstPointerPublicKey,
        raw_direction: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(IdentityKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
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

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalIdentityKeyStore(
            ctx: $0,
            get_identity_key_pair: ffiShimGetIdentityKeyPair,
            get_local_registration_id: ffiShimGetLocalRegistrationId,
            save_identity: ffiShimSaveIdentity,
            get_identity: ffiShimGetIdentity,
            is_trusted_identity: ffiShimIsTrustedIdentity
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiIdentityKeyStoreStruct(raw: $0))
        }
    }
}

internal func withPreKeyStore<Result>(_ store: PreKeyStore, _ context: StoreContext, _ body: (SignalConstPointerFfiPreKeyStoreStruct) throws -> Result) throws -> Result {
    func ffiShimStorePreKey(
        storeCtx: UnsafeMutableRawPointer?,
        id: UInt32,
        record: SignalConstPointerPreKeyRecord
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(PreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = PreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storePreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadPreKey(
        storeCtx: UnsafeMutableRawPointer?,
        recordp: UnsafeMutablePointer<SignalMutPointerPreKeyRecord>?,
        id: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(PreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = try store.loadPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    func ffiShimRemovePreKey(
        storeCtx: UnsafeMutableRawPointer?,
        id: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(PreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            try store.removePreKey(id: id, context: context)
            return 0
        }
    }

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalPreKeyStore(
            ctx: $0,
            load_pre_key: ffiShimLoadPreKey,
            store_pre_key: ffiShimStorePreKey,
            remove_pre_key: ffiShimRemovePreKey
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiPreKeyStoreStruct(raw: $0))
        }
    }
}

internal func withSignedPreKeyStore<Result>(_ store: SignedPreKeyStore, _ context: StoreContext, _ body: (SignalConstPointerFfiSignedPreKeyStoreStruct) throws -> Result) throws -> Result {
    func ffiShimStoreSignedPreKey(
        storeCtx: UnsafeMutableRawPointer?,
        id: UInt32,
        record: SignalConstPointerSignedPreKeyRecord
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SignedPreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = SignedPreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSignedPreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadSignedPreKey(
        storeCtx: UnsafeMutableRawPointer?,
        recordp: UnsafeMutablePointer<SignalMutPointerSignedPreKeyRecord>?,
        id: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SignedPreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = try store.loadSignedPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalSignedPreKeyStore(
            ctx: $0,
            load_signed_pre_key: ffiShimLoadSignedPreKey,
            store_signed_pre_key: ffiShimStoreSignedPreKey
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiSignedPreKeyStoreStruct(raw: $0))
        }
    }
}

internal func withKyberPreKeyStore<Result>(_ store: KyberPreKeyStore, _ context: StoreContext, _ body: (SignalConstPointerFfiKyberPreKeyStoreStruct) throws -> Result) throws -> Result {
    func ffiShimStoreKyberPreKey(
        storeCtx: UnsafeMutableRawPointer?,
        id: UInt32,
        record: SignalConstPointerKyberPreKeyRecord
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(KyberPreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = KyberPreKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeKyberPreKey(record, id: id, context: context)
            return 0
        }
    }

    func ffiShimLoadKyberPreKey(
        storeCtx: UnsafeMutableRawPointer?,
        recordp: UnsafeMutablePointer<SignalMutPointerKyberPreKeyRecord>?,
        id: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(KyberPreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var record = try store.loadKyberPreKey(id: id, context: context)
            recordp!.pointee = try cloneOrTakeHandle(from: &record)
            return 0
        }
    }

    func ffiShimMarkKyberPreKeyUsed(
        storeCtx: UnsafeMutableRawPointer?,
        id: UInt32
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(KyberPreKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            try store.markKyberPreKeyUsed(id: id, context: context)
            return 0
        }
    }

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalKyberPreKeyStore(
            ctx: $0,
            load_kyber_pre_key: ffiShimLoadKyberPreKey,
            store_kyber_pre_key: ffiShimStoreKyberPreKey,
            mark_kyber_pre_key_used: ffiShimMarkKyberPreKeyUsed
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiKyberPreKeyStoreStruct(raw: $0))
        }
    }
}

internal func withSessionStore<Result>(_ store: SessionStore, _ context: StoreContext, _ body: (SignalConstPointerFfiSessionStoreStruct) throws -> Result) throws -> Result {
    func ffiShimStoreSession(
        storeCtx: UnsafeMutableRawPointer?,
        address: SignalConstPointerProtocolAddress,
        record: SignalConstPointerSessionRecord
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SessionStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            var record = SessionRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSession(record, for: address, context: context)
            return 0
        }
    }

    func ffiShimLoadSession(
        storeCtx: UnsafeMutableRawPointer?,
        recordp: UnsafeMutablePointer<SignalMutPointerSessionRecord>?,
        address: SignalConstPointerProtocolAddress
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SessionStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var address = ProtocolAddress(borrowing: address)
            defer { cloneOrForgetAsNeeded(&address) }
            if var record = try store.loadSession(for: address, context: context) {
                recordp!.pointee = try cloneOrTakeHandle(from: &record)
            } else {
                recordp!.pointee = SignalMutPointerSessionRecord()
            }
            return 0
        }
    }

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalSessionStore(
            ctx: $0,
            load_session: ffiShimLoadSession,
            store_session: ffiShimStoreSession
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiSessionStoreStruct(raw: $0))
        }
    }
}

internal func withSenderKeyStore<Result>(_ store: SenderKeyStore, _ context: StoreContext, _ body: (SignalConstPointerFfiSenderKeyStoreStruct) throws -> Result) rethrows -> Result {
    func ffiShimStoreSenderKey(
        storeCtx: UnsafeMutableRawPointer?,
        sender: SignalConstPointerProtocolAddress,
        distributionId: UnsafePointer<uuid_t>?,
        record: SignalConstPointerSenderKeyRecord
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SenderKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var sender = ProtocolAddress(borrowing: sender)
            let distributionId = UUID(uuid: distributionId!.pointee)
            defer { cloneOrForgetAsNeeded(&sender) }
            var record = SenderKeyRecord(borrowing: record)
            defer { cloneOrForgetAsNeeded(&record) }
            try store.storeSenderKey(from: sender, distributionId: distributionId, record: record, context: context)
            return 0
        }
    }

    func ffiShimLoadSenderKey(
        storeCtx: UnsafeMutableRawPointer?,
        recordp: UnsafeMutablePointer<SignalMutPointerSenderKeyRecord>?,
        sender: SignalConstPointerProtocolAddress,
        distributionId: UnsafePointer<uuid_t>?
    ) -> Int32 {
        let storeContext = storeCtx!.assumingMemoryBound(to: ErrorHandlingContext<(SenderKeyStore, StoreContext)>.self)
        return storeContext.pointee.catchCallbackErrors { store, context in
            var sender = ProtocolAddress(borrowing: sender)
            let distributionId = UUID(uuid: distributionId!.pointee)
            defer { cloneOrForgetAsNeeded(&sender) }
            if var record = try store.loadSenderKey(from: sender, distributionId: distributionId, context: context) {
                recordp!.pointee = try cloneOrTakeHandle(from: &record)
            } else {
                recordp!.pointee = SignalMutPointerSenderKeyRecord()
            }
            return 0
        }
    }

    return try rethrowCallbackErrors((store, context)) {
        var ffiStore = SignalSenderKeyStore(
            ctx: $0,
            load_sender_key: ffiShimLoadSenderKey,
            store_sender_key: ffiShimStoreSenderKey
        )
        return try withUnsafePointer(to: &ffiStore) {
            try body(SignalConstPointerFfiSenderKeyStoreStruct(raw: $0))
        }
    }
}
