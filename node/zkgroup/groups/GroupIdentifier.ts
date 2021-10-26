import ByteArray from '../internal/ByteArray';

export default class GroupIdentifier extends ByteArray {

  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, GroupIdentifier.SIZE, true);
  }
}
