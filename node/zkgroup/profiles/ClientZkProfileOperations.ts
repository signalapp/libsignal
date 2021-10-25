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
import ServerPublicParams from '../ServerPublicParams';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext';
import ProfileKey from './ProfileKey';
import ProfileKeyCredential from './ProfileKeyCredential';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import GroupSecretParams from '../groups/GroupSecretParams';
import ProfileKeyCredentialResponse from './ProfileKeyCredentialResponse';

import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ClientZkProfileOperations {

  serverPublicParams: ServerPublicParams

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  createProfileKeyCredentialRequestContext(uuid: UUIDType, profileKey: ProfileKey): ProfileKeyCredentialRequestContext {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.createProfileKeyCredentialRequestContextWithRandom(random, uuid, profileKey);
  }

  createProfileKeyCredentialRequestContextWithRandom(random: FFICompatArrayType, uuid: UUIDType, profileKey: ProfileKey): ProfileKeyCredentialRequestContext {
    const newContents = new FFICompatArray(ProfileKeyCredentialRequestContext.SIZE);

    const serverPublicParamsContents = this.serverPublicParams.getContents();
    const uuidContents = fromUUID(uuid);
    const profileKeyContents = profileKey.getContents();

    const ffi_return = Native.FFI_ServerPublicParams_createProfileKeyCredentialRequestContextDeterministic(serverPublicParamsContents, serverPublicParamsContents.length, random, random.length, uuidContents, uuidContents.length, profileKeyContents, profileKeyContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new ProfileKeyCredentialRequestContext(newContents);
  }

  receiveProfileKeyCredential(profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext, profileKeyCredentialResponse: ProfileKeyCredentialResponse): ProfileKeyCredential {
    const newContents = new FFICompatArray(ProfileKeyCredential.SIZE);

    const serverPublicParamsContents = this.serverPublicParams.getContents();
    const profileKeyCredentialRequestContextContents = profileKeyCredentialRequestContext.getContents();
    const profileKeyCredentialResponseContents = profileKeyCredentialResponse.getContents();

    const ffi_return = Native.FFI_ServerPublicParams_receiveProfileKeyCredential(serverPublicParamsContents, serverPublicParamsContents.length, profileKeyCredentialRequestContextContents, profileKeyCredentialRequestContextContents.length, profileKeyCredentialResponseContents, profileKeyCredentialResponseContents.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new ProfileKeyCredential(newContents);
  }

  createProfileKeyCredentialPresentation(groupSecretParams: GroupSecretParams, profileKeyCredential: ProfileKeyCredential): ProfileKeyCredentialPresentation {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.createProfileKeyCredentialPresentationWithRandom(random, groupSecretParams, profileKeyCredential);
  }

  createProfileKeyCredentialPresentationWithRandom(random: FFICompatArrayType, groupSecretParams: GroupSecretParams, profileKeyCredential: ProfileKeyCredential): ProfileKeyCredentialPresentation {
    const newContents = new FFICompatArray(ProfileKeyCredentialPresentation.SIZE);

    const serverPublicParamsContents = this.serverPublicParams.getContents();
    const groupSecretParamsContents = groupSecretParams.getContents();
    const profileKeyCredentialContents = profileKeyCredential.getContents();

    const ffi_return = Native.FFI_ServerPublicParams_createProfileKeyCredentialPresentationDeterministic(serverPublicParamsContents, serverPublicParamsContents.length, random, random.length, groupSecretParamsContents, groupSecretParamsContents.length, profileKeyCredentialContents, profileKeyCredentialContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError("FFI_RETURN!=OK");
    }

    return new ProfileKeyCredentialPresentation(newContents);
  }

}
