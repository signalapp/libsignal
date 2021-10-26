import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCredentialResponse extends ByteArray {

  static SIZE = 457;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredentialResponse.SIZE, true);
    NativeImpl.ProfileKeyCredentialResponse_CheckValidContents(contents);
  }

}
