import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';


export default class ProfileKeyCredentialRequestContext extends ByteArray {

  static SIZE = 473;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredentialRequestContext.SIZE, true);
    NativeImpl.ProfileKeyCredentialRequestContext_CheckValidContents(contents);
  }

  getRequest(): ProfileKeyCredentialRequest {
    return new ProfileKeyCredentialRequest(NativeImpl.ProfileKeyCredentialRequestContext_GetRequest(this.contents));
  }
}
