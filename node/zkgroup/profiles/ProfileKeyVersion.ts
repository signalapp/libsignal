import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

export default class ProfileKeyVersion extends ByteArray {

  static SIZE = 64;

  constructor(contents: FFICompatArrayType | string) {
    super(typeof contents === 'string' ? new FFICompatArray(Buffer.from(contents)) : contents, ProfileKeyVersion.SIZE, false);
  }

  toString(): string {
    return this.contents.buffer.toString('utf8');
  }

}
