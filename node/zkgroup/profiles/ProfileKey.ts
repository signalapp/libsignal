import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyVersion from './ProfileKeyVersion';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ProfileKey extends ByteArray {

  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, ProfileKey.SIZE, true);
  }

  getCommitment(uuid: UUIDType): ProfileKeyCommitment {
    return new ProfileKeyCommitment(NativeImpl.ProfileKey_GetCommitment(this.contents, fromUUID(uuid)));
  }

  getProfileKeyVersion(uuid: UUIDType): ProfileKeyVersion {
    return new ProfileKeyVersion(NativeImpl.ProfileKey_GetProfileKeyVersion(this.contents, fromUUID(uuid)));
  }
}
