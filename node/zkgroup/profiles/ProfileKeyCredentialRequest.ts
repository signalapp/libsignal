import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCredentialRequest extends ByteArray {

  static SIZE = 329;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredentialRequest.SIZE, true);
    NativeImpl.ProfileKeyCredentialRequest_CheckValidContents(contents);
  }

}
