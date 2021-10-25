export const UUID_LENGTH = 16;
import FFICompatArray, { FFICompatArrayType } from './FFICompatArray';

export type UUIDType = string;

export function toUUID(array: FFICompatArrayType): UUIDType {
  const hex = array.buffer.toString('hex');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export function fromUUID(uuid: UUIDType): FFICompatArrayType {
  let i = 0;
  let array = new FFICompatArray(16);

  uuid.replace(/[0-9A-F]{2}/ig, (oct: string): string => {
      array[i++] = parseInt(oct, 16);
      return '';
  });

  return array;
}
