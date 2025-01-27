import {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} from 'poseidon-lite';
import { sha224, sha256 } from 'js-sha256';
import { sha1 } from 'js-sha1';
import { sha384, sha512 } from 'js-sha512';
import { hexToSignedBytes, packBytesArray } from './bytes';
import * as forge from 'node-forge';

export function flexiblePoseidon(inputs: bigint[]): bigint {
  switch (inputs.length) {
    case 1:
      return poseidon1(inputs);
    case 2:
      return poseidon2(inputs);
    case 3:
      return poseidon3(inputs);
    case 4:
      return poseidon4(inputs);
    case 5:
      return poseidon5(inputs);
    case 6:
      return poseidon6(inputs);
    case 7:
      return poseidon7(inputs);
    case 8:
      return poseidon8(inputs);
    case 9:
      return poseidon9(inputs);
    case 10:
      return poseidon10(inputs);
    case 11:
      return poseidon11(inputs);
    case 12:
      return poseidon12(inputs);
    case 13:
      return poseidon13(inputs);
    case 14:
      return poseidon14(inputs);
    case 15:
      return poseidon15(inputs);
    case 16:
      return poseidon16(inputs);
    default:
      throw new Error(`Unsupported number of inputs: ${inputs.length}`);
  }
}

// hash function - crypto is not supported in react native
export function hash(
  hashFunction: string,
  bytesArray: number[],
  format: string = 'bytes'
): string | number[] {
  const unsignedBytesArray = bytesArray.map((byte) => byte & 0xff);
  let hashResult: string;

  switch (hashFunction) {
    case 'sha1':
      hashResult = sha1(unsignedBytesArray);
      break;
    case 'sha224':
      hashResult = sha224(unsignedBytesArray);
      break;
    case 'sha256':
      hashResult = sha256(unsignedBytesArray);
      break;
    case 'sha384':
      hashResult = sha384(unsignedBytesArray);
      break;
    case 'sha512':
      hashResult = sha512(unsignedBytesArray);
      break;
    default:
      console.log('\x1b[31m%s\x1b[0m', `${hashFunction} not found in hash`); // Log in red
      hashResult = sha256(unsignedBytesArray); // Default to sha256
  }
  if (format === 'hex') {
    return hashResult;
  }
  if (format === 'bytes') {
    return hexToSignedBytes(hashResult);
  }
  if (format === 'binary') {
    return forge.util.binary.raw.encode(new Uint8Array(hexToSignedBytes(hashResult)));
  }
  throw new Error(`Invalid format: ${format}`);
}

export function getHashLen(hashFunction: string) {
  switch (hashFunction) {
    case 'sha1':
      return 20;
    case 'sha224':
      return 28;
    case 'sha256':
      return 32;
    case 'sha384':
      return 48;
    case 'sha512':
      return 64;
    default:
      console.log(`${hashFunction} not found in getHashLen`);
      return 32;
  }
}

export function customHasher(pubKeyFormatted: string[]) {
  if (pubKeyFormatted.length < 16) {
    // if k is less than 16, we can use a single poseidon hash
    return flexiblePoseidon(pubKeyFormatted.map(BigInt)).toString();
  } else {
    const rounds = Math.ceil(pubKeyFormatted.length / 16); // do up to 16 rounds of poseidon
    if (rounds > 16) {
      throw new Error('Number of rounds is greater than 16');
    }
    const hash = new Array(rounds);
    for (let i = 0; i < rounds; i++) {
      hash[i] = { inputs: new Array(16).fill(BigInt(0)) };
    }
    for (let i = 0; i < rounds; i++) {
      for (let j = 0; j < 16; j++) {
        if (i * 16 + j < pubKeyFormatted.length) {
          hash[i].inputs[j] = BigInt(pubKeyFormatted[i * 16 + j]);
        }
      }
    }
    const finalHash = flexiblePoseidon(hash.map((h) => poseidon16(h.inputs)));
    return finalHash.toString();
  }
}

export function packBytesAndPoseidon(unpacked: number[]) {
  const packed = packBytesArray(unpacked);
  return customHasher(packed.map(String)).toString();
}