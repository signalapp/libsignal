import SignalFfi

public func hkdf(outputLength: Int,
                 version: UInt32,
                 inputKeyMaterial: [UInt8],
                 salt: [UInt8],
                 info: [UInt8]) throws -> [UInt8] {

    var output = Array(repeating: UInt8(0x00), count: outputLength)

    let error = signal_hkdf_derive(&output,
                                   outputLength,
                                   Int32(version),
                                   inputKeyMaterial,
                                   inputKeyMaterial.count,
                                   info,
                                   info.count,
                                   salt,
                                   salt.count)

    try checkError(error)

    return output
}
