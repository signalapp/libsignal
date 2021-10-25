import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import VerificationFailedException from '../errors/VerificationFailedException';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import GroupIdentifier from './GroupIdentifier';


export default class GroupPublicParams extends ByteArray {

  static SIZE = 97;

  constructor(contents: FFICompatArrayType) {
    super(contents, GroupPublicParams.SIZE, true);

    const ffi_return = Native.FFI_GroupPublicParams_checkValidContents(this.contents, this.contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }

  getGroupIdentifier(): GroupIdentifier {
    const newContents = new FFICompatArray(GroupIdentifier.SIZE);

    const ffi_return = Native.FFI_GroupPublicParams_getGroupIdentifier(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new GroupIdentifier(newContents);
  }

}
