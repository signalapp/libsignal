declare module 'node-gyp-build' {
  export default function load(path: string): any;
}

declare module '@signalapp/libsignal-client-*' {
  export default {} as unknown;
}
