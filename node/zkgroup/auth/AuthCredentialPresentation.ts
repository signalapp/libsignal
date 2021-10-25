import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation extends ByteArray {

  static SIZE = 493;

  constructor(contents: FFICompatArrayType) {
    super(contents, AuthCredentialPresentation.SIZE, true);

    const ffi_return = Native.FFI_AuthCredentialPresentation_checkValidContents(contents, contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException("FFI_RETURN_INPUT_ERROR");
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }
  }

  getUuidCiphertext(): UuidCiphertext {
    const newContents = new FFICompatArray(UuidCiphertext.SIZE);

    const ffi_return = Native.FFI_AuthCredentialPresentation_getUuidCiphertext(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new UuidCiphertext(newContents);
  }

  getRedemptionTime(): number {
    const newContents = new FFICompatArray(Buffer.alloc(4));

    const ffi_return = Native.FFI_AuthCredentialPresentation_getRedemptionTime(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
     }

    return newContents.buffer.readInt32BE(0);
  }
}
