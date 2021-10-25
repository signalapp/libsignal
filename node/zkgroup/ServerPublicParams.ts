import ByteArray from './internal/ByteArray';

import IllegalArgumentException from './errors/IllegalArgumentException';
import ZkGroupError from './errors/ZkGroupError';
import VerificationFailedException from './errors/VerificationFailedException';

import NotarySignature from './NotarySignature';
import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from './internal/Native';

import FFICompatArray, { FFICompatArrayType } from './internal/FFICompatArray'

export default class ServerPublicParams extends ByteArray {

  static SIZE = 225;

  constructor (contents: FFICompatArrayType)  {
    super(contents, ServerPublicParams.SIZE, true);

    var ffi_return = Native.FFI_ServerPublicParams_checkValidContents(contents, contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new IllegalArgumentException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }
  }

  verifySignature(message: FFICompatArrayType, notarySignature: NotarySignature) {
    const notarySignatureContents = notarySignature.getContents();

    var ffi_return = Native.FFI_ServerPublicParams_verifySignature(this.contents, this.contents.length, message, message.length, notarySignatureContents, notarySignatureContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('Signature failed');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }
  }

  serialize(): FFICompatArrayType {
    return new FFICompatArray(Buffer.from(this.contents.buffer));
  }

}


