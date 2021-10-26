import ByteArray from '../internal/ByteArray';

export default class GroupMasterKey extends ByteArray {

  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, GroupMasterKey.SIZE, true);
  }
}
