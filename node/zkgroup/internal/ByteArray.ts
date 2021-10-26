import { SignalClientErrorBase } from "../../Errors";

export default class ByteArray {
  contents: Buffer;

  constructor(contents: Buffer, expectedLength: number, unrecoverable: boolean) {
    if (contents.length !== expectedLength) {
        throw new SignalClientErrorBase(`Length of array supplied was ${contents.length} expected ${expectedLength}`, undefined, this.constructor.name);
    }
    this.contents = Buffer.from(contents);
  }

  public getContents(): Buffer {
    return this.contents;
  }

  public serialize(): Buffer {
    return Buffer.from(this.contents)
  }
}
