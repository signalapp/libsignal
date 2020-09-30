
class InMemorySenderKeyStore : SenderKeyStore {
    private var map : [SenderKeyName : SenderKeyRecord] = [:]

    func saveSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[name] = record
    }
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return map[name]
    }

}
