
import FFICompatArray, { FFICompatArrayType } from './FFICompatArray';
import InvalidInputException from '../errors/InvalidInputException';

export default class ByteArray {
  contents: FFICompatArrayType;

  constructor(contents: FFICompatArrayType, expectedLength: number, unrecoverable: boolean) {
    if (contents.length !== expectedLength) {
        throw new InvalidInputException(`Length of array supplied was ${contents.length} expected ${expectedLength}`);
    }
    this.contents = new FFICompatArray(Buffer.from(contents.buffer), expectedLength);
  }

  public getContents(): FFICompatArrayType {
    return this.contents;
  }

  public serialize(): FFICompatArrayType {
    // Note: we can't relay on Buffer.slice, since it returns a reference to the same
    //   uinderlying memory
    const array = Uint8Array.prototype.slice.call(this.contents.buffer);
    const buffer = Buffer.from(array);
    return new FFICompatArray(buffer);
  }
}
