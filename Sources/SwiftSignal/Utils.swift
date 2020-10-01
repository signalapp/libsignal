import SignalFfi
import Foundation

func invokeFnReturningString(fn: (UnsafeMutablePointer<UnsafePointer<Int8>?>?) -> OpaquePointer?) throws -> String {
    var output : UnsafePointer<Int8>? = nil
    try CheckError(fn(&output))
    let result = String(cString: output!)
    signal_free_string(output)
    return result
}

func invokeFnReturningArray(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> OpaquePointer?) throws -> [UInt8] {
    var output : UnsafePointer<UInt8>? = nil
    var output_len = 0
    try CheckError(fn(&output, &output_len))
    let result = Array(UnsafeBufferPointer(start: output, count: output_len))
    signal_free_buffer(output, output_len)
    return result
}

func invokeFnReturningUInt32(fn: (UnsafeMutablePointer<UInt32>?) -> OpaquePointer?) throws -> UInt32 {
    var output : UInt32 = 0
    try CheckError(fn(&output))
    return output
}

func invokeFnReturningUInt64(fn: (UnsafeMutablePointer<UInt64>?) -> OpaquePointer?) throws -> UInt64 {
    var output : UInt64 = 0
    try CheckError(fn(&output))
    return output
}

func invokeFnReturningPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> PublicKey {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))
    return PublicKey(raw_ptr: pk_handle)
}

func invokeFnReturningPrivateKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> PrivateKey {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))
    return PrivateKey(raw_ptr: pk_handle)
}

func invokeFnReturningOptionalPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> Optional<PublicKey> {
    var pk_handle : OpaquePointer?
    try CheckError(fn(&pk_handle))

    if pk_handle == nil {
        return Optional.none
    } else {
        return Optional.some(PublicKey(raw_ptr: pk_handle))
    }
}

func createIdentityKeyStore(_ store: IdentityKeyStore) throws -> SignalIdentityKeyStore {
    throw SignalError.internal_error("not implemented")
}

class PreKeyStoreWrapper {
    var store: PreKeyStore

    init(store: PreKeyStore) {
        self.store = store
    }

    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> Optional<PreKeyRecord> {
        try store.loadPreKey(id: id, ctx: ctx)
    }

    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        try store.storePreKey(id: id, record: record, ctx: ctx)
    }

    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws {
        try store.removePreKey(id: id, ctx: ctx)
    }
}

func createPreKeyStore(_ store: PreKeyStore) throws -> (SignalPreKeyStore, PreKeyStoreWrapper) {
    func ffiShimStorePreKey(store_ctx: UnsafeMutableRawPointer?,
                                  id: UInt32,
                                  record: OpaquePointer?,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<PreKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<PreKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let record = try store.loadPreKey(id: id, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
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
            let store = Unmanaged<PreKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            try store.removePreKey(id: id, ctx: ctx)
            return 0
        }
        catch {
            return -1
        }
    }



    let wrapper = PreKeyStoreWrapper(store: store)

    return (SignalPreKeyStore(
              ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
              load_pre_key: ffiShimLoadPreKey,
              store_pre_key: ffiShimStorePreKey,
              remove_pre_key: ffiShimRemovePreKey),
            wrapper)
}

class SignedPreKeyStoreWrapper {
    var store: SignedPreKeyStore

    init(store: SignedPreKeyStore) {
        self.store = store
    }

    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> Optional<SignedPreKeyRecord> {
        try store.loadSignedPreKey(id: id, ctx: ctx)
    }

    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        try store.storeSignedPreKey(id: id, record: record, ctx: ctx)
    }
}

func createSignedPreKeyStore(_ store: SignedPreKeyStore) throws -> (SignalSignedPreKeyStore, SignedPreKeyStoreWrapper) {
    func ffiShimStoreSignedPreKey(store_ctx: UnsafeMutableRawPointer?,
                                  id: UInt32,
                                  record: OpaquePointer?,
                                  ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<SignedPreKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<SignedPreKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let record = try store.loadSignedPreKey(id: id, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    let wrapper = SignedPreKeyStoreWrapper(store: store)

    return (SignalSignedPreKeyStore(
      ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
      load_signed_pre_key: ffiShimLoadSignedPreKey,
      store_signed_pre_key: ffiShimStoreSignedPreKey), wrapper)
}

class SessionStoreWrapper {
    var store: SessionStore

    init(store: SessionStore) {
        self.store = store
    }

    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord> {
        try store.loadSession(address: address, ctx: ctx)
    }

    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws {
        try store.storeSession(address: address, record: record, ctx: ctx)
    }
}

func createSessionStore(_ store: SessionStore) throws -> (SignalSessionStore, SessionStoreWrapper) {
    func ffiShimStoreSession(store_ctx: UnsafeMutableRawPointer?,
                             address: OpaquePointer?,
                             record: OpaquePointer?,
                             ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<SessionStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<SessionStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let address = try ProtocolAddress(clone_from: address)
            let record = try store.loadSession(address: address, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    let wrapper = SessionStoreWrapper(store: store)

    return (SignalSessionStore(
      ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
      load_session: ffiShimLoadSession,
      store_session: ffiShimStoreSession), wrapper)
}


class SenderKeyStoreWrapper {
    var store: SenderKeyStore

    init(store: SenderKeyStore) {
        self.store = store
    }

    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        try store.storeSenderKey(name: name, record: record, ctx: ctx)
    }

    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> Optional<SenderKeyRecord> {
        try store.loadSenderKey(name: name, ctx: ctx)
    }
}

func createSenderKeyStore(_ store: SenderKeyStore) throws -> (SignalSenderKeyStore,SenderKeyStoreWrapper) {
    func ffiShimStoreSenderKey(store_ctx: UnsafeMutableRawPointer?,
                               sender_name: OpaquePointer?,
                               record: OpaquePointer?,
                               ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<SenderKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<SenderKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let sender_name = try SenderKeyName(clone_from: sender_name)
            let record = try store.loadSenderKey(name: sender_name, ctx: ctx)
            recordp!.pointee = record?.leakNativeHandle()
            return 0
        }
        catch {
            return -1
        }
    }

    let wrapper = SenderKeyStoreWrapper(store: store)

    return (SignalSenderKeyStore(
      ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
      load_sender_key: ffiShimLoadSenderKey,
      store_sender_key: ffiShimStoreSenderKey), wrapper)
}
