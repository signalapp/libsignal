import { FFICompatArrayType } from './internal/FFICompatArray';
import ByteArray from './internal/ByteArray';

export default class NotarySignature extends ByteArray {

  static SIZE = 64;

  constructor(contents: FFICompatArrayType) {
    super(contents, NotarySignature.SIZE, true);
  }
}
