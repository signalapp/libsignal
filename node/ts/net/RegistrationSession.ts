//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';

export type RegistrationSessionState = {
  allowedToRequestCode: boolean;
  verified: boolean;
  nextSmsSecs?: number;
  nextCallSecs?: number;
  nextVerificationAttemptSecs?: number;
  requestedInformation: Set<'pushChallenge' | 'captcha'>;
};

export function convertNativeRegistrationSessionState(
  session: Native.Wrapper<Native.RegistrationSession>
): RegistrationSessionState {
  const nextCallSecs = Native.RegistrationSession_GetNextCallSeconds(session);
  const nextSmsSecs = Native.RegistrationSession_GetNextSmsSeconds(session);
  const nextVerificationAttemptSecs =
    Native.RegistrationSession_GetNextVerificationAttemptSeconds(session);

  return {
    allowedToRequestCode:
      Native.RegistrationSession_GetAllowedToRequestCode(session),
    verified: Native.RegistrationSession_GetVerified(session),
    nextCallSecs: nextCallSecs != null ? nextCallSecs : undefined,
    nextSmsSecs: nextSmsSecs != null ? nextSmsSecs : undefined,
    nextVerificationAttemptSecs:
      nextVerificationAttemptSecs != null
        ? nextVerificationAttemptSecs
        : undefined,
    requestedInformation: new Set(
      Native.RegistrationSession_GetRequestedInformation(session)
    ),
  };
}
