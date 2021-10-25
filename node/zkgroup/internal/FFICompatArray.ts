import { types } from 'ref-napi';

import ArrayType = require('ref-array-napi');

// Typescript complains that RefArray is not constructable. But it very much is
const FFICompatArray: ArrayType<number> = ArrayType(types.uint8)

export default FFICompatArray;

export type FFICompatArrayType = ReturnType<typeof FFICompatArray>