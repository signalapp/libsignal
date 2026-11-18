//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { createRequire } from 'node:module';
import load from 'node-gyp-build';

function loadAppropriateNativeModule(): unknown {
  const platform = process.platform;
  switch (platform) {
    case 'darwin':
    case 'linux':
    case 'win32': {
      // Avoid `await import` here to remain esbuild/tsx-compatible.
      const require = createRequire(import.meta.url);
      const importedModule =
        require(`@signalapp/libsignal-client-${platform}`) as {
          default: unknown;
        };
      return importedModule.default;
    }
    default:
      // For platforms not known to have a subpackage, assume the prebuilds live directly in this package.
      return load(`${import.meta.dirname}/..`);
  }
}

export default loadAppropriateNativeModule();
