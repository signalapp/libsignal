//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Intended to be run with @indutny/bencher.
// Can be run under Chrome's Dev Tools (chrome://inspect) using the following:
// % node --inspect-brk node_modules/@indutny/bencher/dist/bin/bencher.js dist/bench/GroupSendEndorsement-receiveWithCiphertexts.js

import {
  groupCiphertexts,
  response,
  serverPublicParams,
} from './support/GroupSendEndorsementHelpers';

export const name = 'GroupSendEndorsement-receiveWithCiphertexts';

export default (): number => {
  return response.receiveWithCiphertexts(
    groupCiphertexts,
    groupCiphertexts[0],
    serverPublicParams
  ).endorsements.length;
};
