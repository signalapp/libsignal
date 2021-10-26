import ByteArray from '../internal/ByteArray';

export default class ProfileKeyVersion extends ByteArray {

  static SIZE = 64;

  constructor(contents: Buffer | string) {
    super(typeof contents === 'string' ? Buffer.from(contents) : contents, ProfileKeyVersion.SIZE, false);
  }

  toString(): string {
    return this.contents.toString('utf8');
  }

}
