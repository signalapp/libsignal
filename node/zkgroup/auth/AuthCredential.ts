import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class AuthCredential extends ByteArray {

  static SIZE = 181;

  constructor(contents: Buffer) {
    super(contents, AuthCredential.SIZE, true);
    NativeImpl.AuthCredential_CheckValidContents(contents);
  }
}
