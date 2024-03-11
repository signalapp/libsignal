//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Intended to be run with @indutny/bencher.
// Can be run under Chrome's Dev Tools (chrome://inspect) using the following:
// % node --inspect-brk node_modules/@indutny/bencher/dist/bin/bencher.js dist/bench/GroupSendEndorsement-receiveWithServiceIds.js

import {
  groupMembers,
  groupSecretParams,
  response,
  serverPublicParams,
} from './support/GroupSendEndorsementHelpers';

export const name = 'GroupSendEndorsement-receiveWithServiceIds';

export default (): number => {
  return response.receiveWithServiceIds(
    groupMembers,
    groupMembers[0],
    groupSecretParams,
    serverPublicParams
  ).endorsements.length;
};
