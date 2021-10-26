import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import UuidCiphertext from '../groups/UuidCiphertext';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext';

export default class ProfileKeyCredentialPresentation extends ByteArray {

  static SIZE = 713;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredentialPresentation.SIZE, true);
    NativeImpl.ProfileKeyCredentialPresentation_CheckValidContents(contents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(NativeImpl.ProfileKeyCredentialPresentation_GetUuidCiphertext(this.contents));
  }

  getProfileKeyCiphertext(): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(NativeImpl.ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(this.contents));
  }

}
