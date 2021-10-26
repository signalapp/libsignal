import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCredential extends ByteArray {

  static SIZE = 145;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredential.SIZE, true);
    NativeImpl.ProfileKeyCredential_CheckValidContents(contents);
  }
}
