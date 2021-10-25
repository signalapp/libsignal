import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyVersion from './ProfileKeyVersion';
import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ProfileKey extends ByteArray {

  static SIZE = 32;

  constructor(contents: FFICompatArrayType) {
    super(contents, ProfileKey.SIZE, true);
  }

  getCommitment(uuid: UUIDType): ProfileKeyCommitment {
    const newContents = new FFICompatArray(ProfileKeyCommitment.SIZE);
    const uuidContents = fromUUID(uuid);

    const ffi_return = Native.FFI_ProfileKey_getCommitment(this.contents, this.contents.length, uuidContents, uuidContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKeyCommitment(newContents);
  }

  getProfileKeyVersion(uuid: UUIDType): ProfileKeyVersion {
    const newContents = new FFICompatArray(ProfileKeyVersion.SIZE);
    const uuidContents = fromUUID(uuid);

    const ffi_return = Native.FFI_ProfileKey_getProfileKeyVersion(this.contents, this.contents.length, uuidContents, uuidContents.length,newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKeyVersion(newContents);
  }
}
