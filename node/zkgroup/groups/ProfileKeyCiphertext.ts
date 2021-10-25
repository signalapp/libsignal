import ByteArray from '../internal/ByteArray';
import { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

export default class ProfileKeyCiphertext extends ByteArray {

  static SIZE = 65;

  constructor(contents: FFICompatArrayType) {
    super(contents, ProfileKeyCiphertext.SIZE, true);

    const ffi_return = Native.FFI_ProfileKeyCiphertext_checkValidContents(this.contents, this.contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }
}
