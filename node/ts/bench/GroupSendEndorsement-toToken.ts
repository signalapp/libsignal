//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Intended to be run with @indutny/bencher.
// Can be run under Chrome's Dev Tools (chrome://inspect) using the following:
// % node --inspect-brk node_modules/@indutny/bencher/dist/bin/bencher.js dist/bench/GroupSendEndorsement-toTokens.js

import {
  groupMembers,
  groupSecretParams,
  response,
  serverPublicParams,
} from './support/GroupSendEndorsementHelpers';

export const name = 'GroupSendEndorsement-toTokens';

const endorsements = response.receiveWithServiceIds(
  groupMembers,
  groupMembers[0],
  groupSecretParams,
  serverPublicParams
);

export default (): number => {
  const tokens = endorsements.endorsements.map((next) =>
    next.toToken(groupSecretParams)
  );
  // Return a dummy integer value to keep the benchmarked code from being optimized away.
  return Number(tokens.every((token) => token.getContents().length != 0));
};
