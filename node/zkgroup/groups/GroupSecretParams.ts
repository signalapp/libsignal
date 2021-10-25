import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import VerificationFailedException from '../errors/VerificationFailedException';
import IllegalArgumentException from '../errors/IllegalArgumentException';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import { RANDOM_LENGTH } from '../internal/Constants';
import GroupIdentifier from './GroupIdentifier';
import GroupMasterKey from './GroupMasterKey';
import GroupPublicParams from './GroupPublicParams';

export default class GroupSecretParams extends ByteArray {

  static SIZE = 289;

  static generate(): GroupSecretParams {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return GroupSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: FFICompatArrayType): GroupSecretParams {
    const newContents = new FFICompatArray(GroupSecretParams.SIZE);

    const ffi_return = Native.FFI_GroupSecretParams_generateDeterministic(random, random.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new GroupSecretParams(newContents);
  }

  static deriveFromMasterKey(groupMasterKey: GroupMasterKey): GroupSecretParams {
    const newContents = new FFICompatArray(GroupSecretParams.SIZE);

    const groupMasterKeyContents = groupMasterKey.getContents();

    const ffi_return = Native.FFI_GroupSecretParams_deriveFromMasterKey(groupMasterKeyContents, groupMasterKeyContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new GroupSecretParams(newContents);
  }

  constructor(contents: FFICompatArrayType)  {
    super(contents, GroupSecretParams.SIZE, true);

    const ffi_return = Native.FFI_GroupSecretParams_checkValidContents(this.contents, this.contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new IllegalArgumentException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }

  getMasterKey(): GroupMasterKey {
    const newContents = new FFICompatArray(GroupMasterKey.SIZE);

    const ffi_return = Native.FFI_GroupSecretParams_getMasterKey(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new GroupMasterKey(newContents);
  }

  getPublicParams(): GroupPublicParams {
    const newContents = new FFICompatArray(GroupPublicParams.SIZE);

    const ffi_return = Native.FFI_GroupSecretParams_getPublicParams(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new GroupPublicParams(newContents);
  }

}
