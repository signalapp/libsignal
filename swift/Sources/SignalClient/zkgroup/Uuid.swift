
public class ZKGUuid : ByteArray {

  static let SIZE: Int = 16

  public required init(contents: [UInt8]) throws  {
    try super.init(newContents: contents, expectedLength: ZKGUuid.SIZE)
  }
}
