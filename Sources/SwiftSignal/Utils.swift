import SignalFfi
import Foundation

func invokeFnReturningString(fn: (UnsafeMutablePointer<UnsafePointer<Int8>?>?) -> OpaquePointer?) throws -> String {
    var output : UnsafePointer<Int8>? = nil;
    try CheckError(fn(&output));
    let result = String(cString: output!);
    signal_free_string(output);
    return result;
}

func invokeFnReturningArray(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> OpaquePointer?) throws -> [UInt8] {
    var output : UnsafePointer<UInt8>? = nil;
    var output_len = 0;
    try CheckError(fn(&output, &output_len));
    let result = Array(UnsafeBufferPointer(start: output, count: output_len));
    signal_free_buffer(output, output_len);
    return result;
}

func invokeFnReturningUInt32(fn: (UnsafeMutablePointer<UInt32>?) -> OpaquePointer?) throws -> UInt32 {
    var output : UInt32 = 0;
    try CheckError(fn(&output));
    return output;
}

func invokeFnReturningUInt64(fn: (UnsafeMutablePointer<UInt64>?) -> OpaquePointer?) throws -> UInt64 {
    var output : UInt64 = 0;
    try CheckError(fn(&output));
    return output;
}

func invokeFnReturningPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> PublicKey {
    var pk_handle : OpaquePointer?;
    try CheckError(fn(&pk_handle));
    return PublicKey(raw_ptr: pk_handle);
}

func invokeFnReturningPrivateKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> PrivateKey {
    var pk_handle : OpaquePointer?;
    try CheckError(fn(&pk_handle));
    return PrivateKey(raw_ptr: pk_handle);
}

func invokeFnReturningOptionalPublicKey(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> OpaquePointer?) throws -> Optional<PublicKey> {
    var pk_handle : OpaquePointer?;
    try CheckError(fn(&pk_handle));

    if pk_handle == nil {
        return Optional.none;
    } else {
        return Optional.some(PublicKey(raw_ptr: pk_handle));
    }
}

func createIdentityKeyStore(_ store: IdentityKeyStore) throws -> SignalIdentityKeyStore {
    throw SignalError.internal_error("not implemented")
}

func createPreKeyStore(_ store: PreKeyStore) throws -> SignalPreKeyStore {
    throw SignalError.internal_error("not implemented")
}

func createSignedPreKeyStore(_ store: SignedPreKeyStore) throws -> SignalSignedPreKeyStore {
    throw SignalError.internal_error("not implemented")
}

func createSessionStore(_ store: SessionStore) throws -> SignalSessionStore {
    throw SignalError.internal_error("not implemented")
}


class SenderKeyStoreWrapper {
    var store: SenderKeyStore;

    init(store: SenderKeyStore) {
        self.store = store;
    }

    func saveSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        try store.saveSenderKey(name: name, record: record, ctx: ctx);
    }

    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> Optional<SenderKeyRecord> {
        try store.loadSenderKey(name: name, ctx: ctx);
    }
}

func createSenderKeyStore(_ store: SenderKeyStore) throws -> (SignalSenderKeyStore,SenderKeyStoreWrapper) {
    func ffiShimStoreSenderKey(store_ctx: UnsafeMutableRawPointer?,
                               sender_name: OpaquePointer?,
                               record: OpaquePointer?,
                               ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<SenderKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let sender_name = try SenderKeyName(clone_from: sender_name);
            let record = try SenderKeyRecord(clone_from: record);
            try store.saveSenderKey(name: sender_name, record: record, ctx: ctx);
            return 0;
        }
        catch {
            return -1;
        }
    }

    func ffiShimLoadSenderKey(store_ctx: UnsafeMutableRawPointer?,
                              recordp: UnsafeMutablePointer<OpaquePointer?>?,
                              sender_name: OpaquePointer?,
                              ctx: UnsafeMutableRawPointer?) -> Int32 {
        do {
            let store = Unmanaged<SenderKeyStoreWrapper>.fromOpaque(store_ctx!).takeUnretainedValue()
            let sender_name = try SenderKeyName(clone_from: sender_name);
            let record = try store.loadSenderKey(name: sender_name, ctx: ctx);
            recordp!.pointee = record?.leakNativeHandle();
            return 0;
        }
        catch {
            return -1;
        }
    }

    let wrapper = SenderKeyStoreWrapper(store: store);

    return (SignalSenderKeyStore(
      ctx: Unmanaged.passUnretained(wrapper).toOpaque(),
      load_sender_key: ffiShimLoadSenderKey,
      store_sender_key: ffiShimStoreSenderKey), wrapper)
}
