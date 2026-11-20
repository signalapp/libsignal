// Keep this file in sync with the other platform implementations!
// (Unfortunately we can't use a symlink because pnpm-publish will strip it out.)
import load from 'node-gyp-build';
export default load(import.meta.dirname);
