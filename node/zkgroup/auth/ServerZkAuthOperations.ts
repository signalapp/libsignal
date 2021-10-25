import { randomBytes } from 'crypto';
import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import VerificationFailedException from '../errors/VerificationFailedException';
import { RANDOM_LENGTH } from '../internal/Constants';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import UuidCiphertext from '../groups/UuidCiphertext';

import ServerSecretParams from '../ServerSecretParams';
import AuthCredentialResponse from './AuthCredentialResponse';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import GroupPublicParams from '../groups/GroupPublicParams';
import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ServerZkAuthOperations {

  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueAuthCredential(uuid: UUIDType, redemptionTime: number): AuthCredentialResponse {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.issueAuthCredentialWithRandom(random, uuid, redemptionTime);
  }

  issueAuthCredentialWithRandom(random: FFICompatArrayType, uuid: UUIDType, redemptionTime: number): AuthCredentialResponse {
    const newContents = new FFICompatArray(AuthCredentialResponse.SIZE);

    const serverParamContents = this.serverSecretParams.getContents();
    const uuidContents = fromUUID(uuid);

    const ffi_return = Native.FFI_ServerSecretParams_issueAuthCredentialDeterministic(serverParamContents, serverParamContents.length, random, random.length, uuidContents, uuidContents.length, redemptionTime, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new AuthCredentialResponse(newContents);
  }

  verifyAuthCredentialPresentation(groupPublicParams: GroupPublicParams, authCredentialPresentation: AuthCredentialPresentation) {
    const serverParamContents = this.serverSecretParams.getContents();
    const groupPublicContents = groupPublicParams.getContents();
    const authCredentialPresentationContents = authCredentialPresentation.getContents();

    const ffi_return = Native.FFI_ServerSecretParams_verifyAuthCredentialPresentation(serverParamContents, serverParamContents.length, groupPublicContents, groupPublicContents.length, authCredentialPresentationContents, authCredentialPresentationContents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }

}
