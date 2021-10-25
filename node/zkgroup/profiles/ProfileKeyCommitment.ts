import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import ProfileKeyVersion from './ProfileKeyVersion';

export default class ProfileKeyCommitment extends ByteArray {

  static SIZE = 97;

  constructor(contents: FFICompatArrayType) {
    super(contents, ProfileKeyCommitment.SIZE, true);

    const ffi_return = Native.FFI_ProfileKeyCommitment_checkValidContents(this.contents, this.contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException("FFI_RETURN_INPUT_ERROR");
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }
  }

}
