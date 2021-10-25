
export default class InvalidInputException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidInputException';
  }
}

