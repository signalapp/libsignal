
export default class AssertionError extends Error {
  constructor(message: string) {
    super();
    this.name = 'AssertionError';
  }
}


