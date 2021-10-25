import { randomBytes } from 'crypto';
import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import VerificationFailedException from '../errors/VerificationFailedException';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import UuidCiphertext from '../groups/UuidCiphertext';

import ServerPublicParams from '../ServerPublicParams';
import AuthCredential from './AuthCredential';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialResponse from './AuthCredentialResponse';
import GroupSecretParams from '../groups/GroupSecretParams';
import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ClientZkAuthOperations {

  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  receiveAuthCredential(uuid: UUIDType, redemptionTime: number, authCredentialResponse: AuthCredentialResponse): AuthCredential {
    const newContents = new FFICompatArray(AuthCredential.SIZE);

    const serverPublicParamsContents = this.serverPublicParams.getContents()
    const uuidContents = fromUUID(uuid);
    const authCredentialResponseContents = authCredentialResponse.getContents();

    const ffi_return = Native.FFI_ServerPublicParams_receiveAuthCredential(serverPublicParamsContents, serverPublicParamsContents.length, uuidContents, uuidContents.length, redemptionTime, authCredentialResponseContents, authCredentialResponseContents.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException("FFI_RETURN_INPUT_ERROR");
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new AuthCredential(newContents);
  }

  createAuthCredentialPresentation(groupSecretParams: GroupSecretParams, authCredential: AuthCredential): AuthCredentialPresentation {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.createAuthCredentialPresentationWithRandom(random, groupSecretParams, authCredential);
  }

  createAuthCredentialPresentationWithRandom(random: FFICompatArrayType, groupSecretParams: GroupSecretParams, authCredential: AuthCredential): AuthCredentialPresentation {
    const newContents = new FFICompatArray(AuthCredentialPresentation.SIZE);

    const serverPublicParamsContents = this.serverPublicParams.getContents()
    const groupSecretParamsContents = groupSecretParams.getContents();
    const authCredentialContents = authCredential.getContents();

    const ffi_return = Native.FFI_ServerPublicParams_createAuthCredentialPresentationDeterministic(serverPublicParamsContents, serverPublicParamsContents.length, random, random.length, groupSecretParamsContents, groupSecretParamsContents.length, authCredentialContents, authCredentialContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new AuthCredentialPresentation(newContents);
  }

}
