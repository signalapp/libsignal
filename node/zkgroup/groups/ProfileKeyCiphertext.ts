import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCiphertext extends ByteArray {

  static SIZE = 65;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCiphertext.SIZE, true);
    NativeImpl.ProfileKeyCiphertext_CheckValidContents(contents);
  }
}
