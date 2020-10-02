import SignalFfi
import Foundation

func invokeFnReturningString(fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?) throws -> String {
    var output : UnsafePointer<Int8>? = nil
    try CheckError(fn(&output))
    let result = String(cString: output!)
    signal_free_string(output)
    return result
}

func invokeFnReturningArray(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> SignalFfiErrorRef?) throws -> [UInt8] {
    var output : UnsafePointer<UInt8>? = nil
    var output_len = 0
    try CheckError(fn(&output, &output_len))
    let result = Array(UnsafeBufferPointer(start: output, count: output_len))
    signal_free_buffer(output, output_len)
    return result
}

func invokeFnReturningInteger<Result: FixedWidthInteger>(fn: (UnsafeMutablePointer<Result>?) -> SignalFfiErrorRef?) throws -> Result {
    var output : Result = 0
    try CheckError(fn(&output))
    return output
}

func invokeFnReturningPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> SignalFfiErrorRef?) throws -> PublicKey {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))
    return PublicKey(raw_ptr: pk_handle)
}

func invokeFnReturningPrivateKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> SignalFfiErrorRef?) throws -> PrivateKey {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))
    return PrivateKey(raw_ptr: pk_handle)
}

func invokeFnReturningOptionalPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> SignalFfiErrorRef?) throws -> Optional<PublicKey> {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))

    if pk_handle == nil {
        return Optional.none
    } else {
        return Optional.some(PublicKey(raw_ptr: pk_handle))
    }
}

func withIdentityKeyStore<Result>(_ store: IdentityKeyStore, _ body: (UnsafePointer<SignalIdentityKeyStore>) throws -> Result) throws -> Result {
    func ffiShimGetIdentityKeyPair(store_ctx: UnsafeMutableRawPointer?,
                                   keyp: UnsafeMutablePointer<OpaquePointer?>?,
                                   ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: IdentityKeyStore.self).pointee
            let key = try store.getIdentityKeyPair(ctx: ctx)
            keyp!.pointee = key.privateKey().leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimGetLocalRegistrationid(store_ctx: UnsafeMutableRawPointer?,
                                       idp: UnsafeMutablePointer<UInt32>?,
                                       ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: IdentityKeyStore.self).pointee
            let id = try store.getLocalRegistrationId(ctx: ctx)
            idp!.pointee = id;
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimSaveIdentity(store_ctx: UnsafeMutableRawPointer?,
                             address: OpaquePointer?,
                             public_key: OpaquePointer?,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: IdentityKeyStore.self).pointee
            let address = try ProtocolAddress(clone_from: address)
            let public_key = try PublicKey(clone_from: public_key)
            let identity = IdentityKey(pk: public_key)
            let new_id = try store.saveIdentity(address: address, identity: identity, ctx: ctx)
            if new_id {
                return 1
            } else {
                return 0
            }
        }
        catch {
            return -1
        }
    }

    func ffiShimGetIdentity(store_ctx: UnsafeMutableRawPointer?,
                            public_key: UnsafeMutablePointer<OpaquePointer?>?,
                            address: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: IdentityKeyStore.self).pointee
            let address = try ProtocolAddress(clone_from: address)
            if let pk = try store.getIdentity(address: address, ctx: ctx) {
                public_key!.pointee = pk.publicKey().leakNativeHandle()
            } else {
                public_key!.pointee = nil
            }
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimIsTrustedIdentity(store_ctx: UnsafeMutableRawPointer?,
                                  address: OpaquePointer?,
                                  public_key: OpaquePointer?,
                                  direction: UInt32,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: IdentityKeyStore.self).pointee
            let address = try ProtocolAddress(clone_from: address)
            let public_key = try PublicKey(clone_from: public_key)
            let direction = direction == 0 ? Direction.Sending : Direction.Receiving
            let identity = IdentityKey(pk: public_key)
            let trusted = try store.isTrustedIdentity(address: address, identity: identity, direction: direction, ctx: ctx)
            return trusted ? 1 : 0
        }
        catch {
            return -1
        }
    }

    return try withUnsafePointer(to: store) {
        // We're not actually going to mutate through 'ffiStore.ctx';
        // it's just the usual convention of `void *` for context fields.
        var ffiStore = SignalIdentityKeyStore(
            ctx: UnsafeMutableRawPointer(mutating: $0),
            get_identity_key_pair: ffiShimGetIdentityKeyPair,
            get_local_registration_id: ffiShimGetLocalRegistrationid,
            save_identity: ffiShimSaveIdentity,
            get_identity: ffiShimGetIdentity,
            is_trusted_identity: ffiShimIsTrustedIdentity)
        return try body(&ffiStore)
    }
}

func withPreKeyStore<Result>(_ store: PreKeyStore, _ body: (UnsafePointer<SignalPreKeyStore>) throws -> Result) throws -> Result {
    func ffiShimStorePreKey(store_ctx: UnsafeMutableRawPointer?,
                            id: UInt32,
                            record: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: PreKeyStore.self).pointee
            let record = try PreKeyRecord(clone_from: record)
            try store.storePreKey(id: id, record: record, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimLoadPreKey(store_ctx: UnsafeMutableRawPointer?,
                           recordp: UnsafeMutablePointer<OpaquePointer?>?,
                           id: UInt32,
                           ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: PreKeyStore.self).pointee
            let record = try store.loadPreKey(id: id, ctx: ctx)
            recordp!.pointee = record.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimRemovePreKey(store_ctx: UnsafeMutableRawPointer?,
                             id: UInt32,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: PreKeyStore.self).pointee
            try store.removePreKey(id: id, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }

    return try withUnsafePointer(to: store) {
        // We're not actually going to mutate through 'ffiStore.ctx';
        // it's just the usual convention of `void *` for context fields.
        var ffiStore = SignalPreKeyStore(
            ctx: UnsafeMutableRawPointer(mutating: $0),
            load_pre_key: ffiShimLoadPreKey,
            store_pre_key: ffiShimStorePreKey,
            remove_pre_key: ffiShimRemovePreKey)
        return try body(&ffiStore)
    }
}

func withSignedPreKeyStore<Result>(_ store: SignedPreKeyStore, _ body: (UnsafePointer<SignalSignedPreKeyStore>) throws -> Result) throws -> Result {
    func ffiShimStoreSignedPreKey(store_ctx: UnsafeMutableRawPointer?,
                                  id: UInt32,
                                  record: OpaquePointer?,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SignedPreKeyStore.self).pointee
            let record = try SignedPreKeyRecord(clone_from: record)
            try store.storeSignedPreKey(id: id, record: record, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimLoadSignedPreKey(store_ctx: UnsafeMutableRawPointer?,
                                 recordp: UnsafeMutablePointer<OpaquePointer?>?,
                                 id: UInt32,
                                 ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SignedPreKeyStore.self).pointee
            let record = try store.loadSignedPreKey(id: id, ctx: ctx)
            recordp!.pointee = record.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    return try withUnsafePointer(to: store) {
        // We're not actually going to mutate through 'ffiStore.ctx';
        // it's just the usual convention of `void *` for context fields.
        var ffiStore = SignalSignedPreKeyStore(
            ctx: UnsafeMutableRawPointer(mutating: $0),
            load_signed_pre_key: ffiShimLoadSignedPreKey,
            store_signed_pre_key: ffiShimStoreSignedPreKey)
        return try body(&ffiStore)
    }
}

func withSessionStore<Result>(_ store: SessionStore, _ body: (UnsafePointer<SignalSessionStore>) throws -> Result) throws -> Result {
    func ffiShimStoreSession(store_ctx: UnsafeMutableRawPointer?,
                             address: OpaquePointer?,
                             record: OpaquePointer?,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SessionStore.self).pointee
            let address = try ProtocolAddress(clone_from: address)
            let record = try SessionRecord(clone_from: record)
            try store.storeSession(address: address, record: record, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimLoadSession(store_ctx: UnsafeMutableRawPointer?,
                            recordp: UnsafeMutablePointer<OpaquePointer?>?,
                            address: OpaquePointer?,
                            ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SessionStore.self).pointee
            let address = try ProtocolAddress(clone_from: address)
            let record = try store.loadSession(address: address, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    return try withUnsafePointer(to: store) {
        // We're not actually going to mutate through 'ffiStore.ctx';
        // it's just the usual convention of `void *` for context fields.
        var ffiStore = SignalSessionStore(
            ctx: UnsafeMutableRawPointer(mutating: $0),
            load_session: ffiShimLoadSession,
            store_session: ffiShimStoreSession)
        return try body(&ffiStore)
    }
}

func withSenderKeyStore<Result>(_ store: SenderKeyStore, _ body: (UnsafePointer<SignalSenderKeyStore>) throws -> Result) rethrows -> Result {
    func ffiShimStoreSenderKey(store_ctx: UnsafeMutableRawPointer?,
                               sender_name: OpaquePointer?,
                               record: OpaquePointer?,
                               ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SenderKeyStore.self).pointee
            let sender_name = try SenderKeyName(clone_from: sender_name)
            let record = try SenderKeyRecord(clone_from: record)
            try store.storeSenderKey(name: sender_name, record: record, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }

    func ffiShimLoadSenderKey(store_ctx: UnsafeMutableRawPointer?,
                              recordp: UnsafeMutablePointer<OpaquePointer?>?,
                              sender_name: OpaquePointer?,
                              ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = store_ctx!.assumingMemoryBound(to: SenderKeyStore.self).pointee
            let sender_name = try SenderKeyName(clone_from: sender_name)
            let record = try store.loadSenderKey(name: sender_name, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    return try withUnsafePointer(to: store) {
        // We're not actually going to mutate through 'ffiStore.ctx';
        // it's just the usual convention of `void *` for context fields.
        var ffiStore = SignalSenderKeyStore(
            ctx: UnsafeMutableRawPointer(mutating: $0),
            load_sender_key: ffiShimLoadSenderKey,
            store_sender_key: ffiShimStoreSenderKey)
        return try body(&ffiStore)
    }
}
