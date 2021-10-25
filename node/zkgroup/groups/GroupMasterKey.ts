import { FFICompatArrayType } from '../internal/FFICompatArray';
import ByteArray from '../internal/ByteArray';

export default class GroupMasterKey extends ByteArray {

  static SIZE = 32;

  constructor(contents: FFICompatArrayType) {
    super(contents, GroupMasterKey.SIZE, true);
  }
}
