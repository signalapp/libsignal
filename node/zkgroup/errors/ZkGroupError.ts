
export default class ZkGroupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZkGroupError';
  }
}
