import ByteArray from './internal/ByteArray';

export default class NotarySignature extends ByteArray {

  static SIZE = 64;

  constructor(contents: Buffer) {
    super(contents, NotarySignature.SIZE, true);
  }
}
