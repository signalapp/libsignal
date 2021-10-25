import { randomBytes } from 'crypto';
import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import VerificationFailedException from '../errors/VerificationFailedException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import ServerSecretParams from '../ServerSecretParams';

import ProfileKeyCredentialResponse from './ProfileKeyCredentialResponse';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import GroupPublicParams from '../groups/GroupPublicParams';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';

import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ServerZkProfileOperations {

  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueProfileKeyCredential(profileKeyCredentialRequest: ProfileKeyCredentialRequest, uuid: UUIDType, profileKeyCommitment: ProfileKeyCommitment): ProfileKeyCredentialResponse{
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.issueProfileKeyCredentialWithRandom(random, profileKeyCredentialRequest, uuid, profileKeyCommitment);
  }

  issueProfileKeyCredentialWithRandom(random: FFICompatArrayType, profileKeyCredentialRequest: ProfileKeyCredentialRequest, uuid: UUIDType, profileKeyCommitment: ProfileKeyCommitment): ProfileKeyCredentialResponse {
    const newContents = new FFICompatArray(ProfileKeyCredentialResponse.SIZE);

    const serverSecretParamsContents = this.serverSecretParams.getContents();
    const profileKeyCredentialRequestContents = profileKeyCredentialRequest.getContents()
    const uuidContents = fromUUID(uuid);
    const profileKeyCommitmentContents = profileKeyCommitment.getContents()

    const ffi_return = Native.FFI_ServerSecretParams_issueProfileKeyCredentialDeterministic(serverSecretParamsContents, serverSecretParamsContents.length, random, random.length, profileKeyCredentialRequestContents, profileKeyCredentialRequestContents.length, uuidContents, uuidContents.length, profileKeyCommitmentContents, profileKeyCommitmentContents.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKeyCredentialResponse(newContents);
  }

  verifyProfileKeyCredentialPresentation(groupPublicParams: GroupPublicParams, profileKeyCredentialPresentation: ProfileKeyCredentialPresentation ) {
    const serverSecretParamsContents = this.serverSecretParams.getContents()
    const groupPublicParamsContents = groupPublicParams.getContents()
    const profileKeyCredentialPresentationContents = profileKeyCredentialPresentation.getContents();

    const ffi_return = Native.FFI_ServerSecretParams_verifyProfileKeyCredentialPresentation(serverSecretParamsContents, serverSecretParamsContents.length, groupPublicParamsContents, groupPublicParamsContents.length, profileKeyCredentialPresentationContents, profileKeyCredentialPresentationContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }

}
