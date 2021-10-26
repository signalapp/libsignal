import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
export default class AuthCredentialResponse extends ByteArray {

  static SIZE = 361;

  constructor(contents: Buffer) {
    super(contents, AuthCredentialResponse.SIZE, true);
    NativeImpl.AuthCredentialResponse_CheckValidContents(contents);
  }
}
