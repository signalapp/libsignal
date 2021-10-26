import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCommitment extends ByteArray {

  static SIZE = 97;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCommitment.SIZE, true);
    NativeImpl.ProfileKeyCommitment_CheckValidContents(contents);
  }

}
