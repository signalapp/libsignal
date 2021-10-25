
export default class VerificationFailedException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VerificationFailedException';
  }
}
