import SignalFfi
import Foundation

func hkdf(output_length: UInt32,
          version: UInt32,
          input_key_material: [UInt8],
          salt: [UInt8],
          info: [UInt8]) throws -> Array<UInt8> {

    var output = Array(repeating: UInt8(0x00), count: Int(output_length))

    let error = signal_hkdf_derive(&output,
                                   Int(output_length),
                                   Int32(version),
                                   input_key_material,
                                   input_key_material.count,
                                   info,
                                   info.count,
                                   salt,
                                   salt.count)


    try CheckError(error)

    return output
}
