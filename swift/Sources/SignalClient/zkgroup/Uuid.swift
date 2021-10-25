
public class ZKGUuid : ByteArray {

  static let SIZE: Int = 16

  public init(contents: [UInt8]) throws  {
    try super.init(newContents: contents, expectedLength: ZKGUuid.SIZE)
  }

  public func serialize() -> [UInt8] {
    return contents
  }
}
