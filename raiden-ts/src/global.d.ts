/* eslint-disable @typescript-eslint/no-explicit-any */

declare module 'matrix-js-sdk/lib/utils' {
  export function encodeUri(pathTemplate: string, variables: { [fragment: string]: any }): string;
}

declare module 'matrix-js-sdk/lib/logger' {
  import { Logger } from 'loglevel';
  export const logger: Logger;
}

declare module 'abort-controller/polyfill';
declare module 'wrtc'; // types provided by @types/webrtc

declare module 'pouchdb-adapter-indexeddb';

declare type Mutable<T> = { -readonly [P in keyof T]: T[P] };
