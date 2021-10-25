import { randomBytes } from 'crypto';
import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from './internal/Native';
import FFICompatArray, { FFICompatArrayType } from './internal/FFICompatArray';
import ByteArray from './internal/ByteArray';

import IllegalArgumentException from './errors/IllegalArgumentException';
import ZkGroupError from './errors/ZkGroupError';
import VerificationFailedException from './errors/VerificationFailedException';
import { RANDOM_LENGTH } from './internal/Constants';
import ServerPublicParams from './ServerPublicParams';
import NotarySignature from './NotarySignature';

export default class ServerSecretParams extends ByteArray {

  static SIZE = 1121;

  static generate(): ServerSecretParams {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return ServerSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: FFICompatArrayType): ServerSecretParams {
    const newContents = new FFICompatArray(ServerSecretParams.SIZE);

    if (random.length !== 32) {
        throw new IllegalArgumentException('random length was not 32');
    }

    if (newContents.length !== ServerSecretParams.SIZE) {
        throw new IllegalArgumentException('newContents was not expected size');
    }

    var ffi_return = Native.FFI_ServerSecretParams_generateDeterministic(random, random.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }

    return new ServerSecretParams(newContents);
  }

  constructor(contents: FFICompatArrayType)  {
    super(contents, ServerSecretParams.SIZE, true);

    var ffi_return = Native.FFI_ServerSecretParams_checkValidContents(contents, contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new IllegalArgumentException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }
  }

  getPublicParams(): ServerPublicParams {
    const newContents = FFICompatArray(ServerPublicParams.SIZE);

    var ffi_return = Native.FFI_ServerSecretParams_getPublicParams(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }

    return new ServerPublicParams(newContents);
  }

  sign(message: FFICompatArrayType): NotarySignature {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.signWithRandom(random, message);
  }

  signWithRandom(random: FFICompatArrayType, message: FFICompatArrayType): NotarySignature {
    const newContents = new FFICompatArray(NotarySignature.SIZE);

    var ffi_return = Native.FFI_ServerSecretParams_signDeterministic(this.contents, this.contents.length, random, random.length, message, message.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN != OK');
    }

    return new NotarySignature(newContents);
  }

  serialize(): FFICompatArrayType {
    return new FFICompatArray(Buffer.from(this.contents.buffer));
  }
}
