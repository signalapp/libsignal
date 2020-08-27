import SignalFfi
import Foundation

class SessionRecord {
    private var handle: OpaquePointer?;

    deinit {
        signal_session_record_destroy(handle);
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_session_record_deserialize(&handle, bytes, bytes.count));
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_session_record_serialize(handle,b,bl) });
    }
}
