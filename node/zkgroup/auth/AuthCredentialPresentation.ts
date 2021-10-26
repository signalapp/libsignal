import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation extends ByteArray {

  static SIZE = 493;

  constructor(contents: Buffer) {
    super(contents, AuthCredentialPresentation.SIZE, true);
    NativeImpl.AuthCredentialPresentation_CheckValidContents(contents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(NativeImpl.AuthCredentialPresentation_GetUuidCiphertext(this.contents));
  }

  getRedemptionTime(): number {
    return NativeImpl.AuthCredentialPresentation_GetRedemptionTime(this.contents);
  }
}
