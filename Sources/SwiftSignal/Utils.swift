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

class IdentityKeyStoreWrapper {
    var store: IdentityKeyStore

    init(store: IdentityKeyStore) {
        self.store = store
    }

    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair {
        return try store.getIdentityKeyPair(ctx: ctx)
    }

    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32 {
        return try store.getLocalRegistrationId(ctx: ctx)
    }

    func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        return try store.saveIdentity(address: address, identity: identity, ctx: ctx)
    }

    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        return try store.isTrustedIdentity(address: address, identity: identity, direction: direction, ctx: ctx)
    }

    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey> {
        return try store.getIdentity(address: address, ctx: ctx)
    }
}

func createIdentityKeyStore(_ store: IdentityKeyStore) throws -> (SignalIdentityKeyStore, IdentityKeyStoreWrapper) {
    func ffiShimGetIdentityKeyPair(store_ctx: UnsafeMutableRawPointer?,
                                   keyp: UnsafeMutablePointer<OpaquePointer?>?,
                                   ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<IdentityKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<IdentityKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<IdentityKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<IdentityKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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
            let store = Unmanaged<IdentityKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
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

    let wrapper = IdentityKeyStoreWrapper(store: store)

    return (SignalIdentityKeyStore(
              ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
              get_identity_key_pair: ffiShimGetIdentityKeyPair,
              get_local_registration_id: ffiShimGetLocalRegistrationid,
              save_identity: ffiShimSaveIdentity,
              get_identity: ffiShimGetIdentity,
              is_trusted_identity: ffiShimIsTrustedIdentity),
            wrapper)
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
