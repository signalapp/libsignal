import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class UuidCiphertext extends ByteArray {

  static SIZE = 65;

  constructor(contents: Buffer) {
    super(contents, UuidCiphertext.SIZE, true);
    NativeImpl.UuidCiphertext_CheckValidContents(contents);
  }

}
