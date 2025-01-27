import { MAX_BYTES_IN_FIELD } from "../constants/constants";

export function packBytes(unpacked) {
    const bytesCount = [31, 31, 31];
    let packed = [0n, 0n, 0n];

    let byteIndex = 0;
    for (let i = 0; i < bytesCount.length; i++) {
        for (let j = 0; j < bytesCount[i]; j++) {
            if (byteIndex < unpacked.length) {
                packed[i] |= BigInt(unpacked[byteIndex]) << (BigInt(j) * 8n);
            }
            byteIndex++;
        }
    }
    return packed;
}
export function computeIntChunkLength(byteLength: number) {
    const packSize = MAX_BYTES_IN_FIELD;
    const remain = byteLength % packSize;
    let numChunks = (byteLength - remain) / packSize;
    if (remain > 0) {
        numChunks += 1;
    }
    return numChunks;
}

export function packBytesArray(unpacked: number[]) {
    const packSize = MAX_BYTES_IN_FIELD;
    const maxBytes = unpacked.length;
    const maxInts = computeIntChunkLength(maxBytes);
    const out: bigint[] = new Array(maxInts).fill(0n);

    for (let i = 0; i < maxInts; i++) {
        let sum = 0n;
        for (let j = 0; j < packSize; j++) {
            const idx = packSize * i + j;

            // Copy previous value if out of bounds
            if (idx >= maxBytes) {
                continue;
            }
            // First item of chunk is byte itself
            else if (j === 0) {
                sum = BigInt(unpacked[idx]);
            }
            // Every other item is 256^j * byte
            else {
                sum += (1n << BigInt(8 * j)) * BigInt(unpacked[idx]);
            }
        }
        out[i] = sum;
    }

    return out;
}

export function toUnsigned(byte: number) {
    return byte & 0xff;
}

export function toSigned(byte: number) {
    return byte > 127 ? byte - 256 : byte;
}

export const toBinaryString = (byte: any) => {
    const binary = (parseInt(byte, 10) & 0xff).toString(2).padStart(8, '0');
    return binary;
};

export function splitToWords(number: bigint, wordsize: number, numberElement: number) {
    let t = number;
    const words: string[] = [];
    for (let i = 0; i < numberElement; ++i) {
        const baseTwo = BigInt(2);

        words.push(`${t % BigInt(Math.pow(Number(baseTwo), wordsize))}`);
        t = BigInt(t / BigInt(Math.pow(Number(BigInt(2)), wordsize)));
    }
    if (!(t == BigInt(0))) {
        throw `Number ${number} does not fit in ${(wordsize * numberElement).toString()} bits`;
    }
    return words;
}

export function bytesToBigDecimal(arr: number[]): string {
    let result = BigInt(0);
    for (let i = 0; i < arr.length; i++) {
        result = result * BigInt(256) + BigInt(arr[i] & 0xff);
    }
    return result.toString();
}

export function hexToDecimal(hex: string): string {
    return BigInt(`0x${hex}`).toString();
}

export function hexToSignedBytes(hexString: string): number[] {
    let bytes = [];
    for (let i = 0; i < hexString.length - 1; i += 2) {
        let byte = parseInt(hexString.substr(i, 2), 16);
        bytes.push(byte >= 128 ? byte - 256 : byte);
    }
    return bytes;
}

export function toUnsignedByte(signedByte: number) {
    return signedByte < 0 ? signedByte + 256 : signedByte;
}

export function bigIntToChunkedBytes(
    num: BigInt | bigint,
    bytesPerChunk: number,
    numChunks: number
) {
    const res: string[] = [];
    const bigintNum: bigint = typeof num == 'bigint' ? num : num.valueOf();
    const msk = (1n << BigInt(bytesPerChunk)) - 1n;
    for (let i = 0; i < numChunks; ++i) {
        res.push(((bigintNum >> BigInt(i * bytesPerChunk)) & msk).toString());
    }
    return res;
}

export function hexStringToSignedIntArray(hexString: string) {
    let result = [];
    for (let i = 0; i < hexString.length; i += 2) {
        let byte = parseInt(hexString.substr(i, 2), 16);
        result.push(byte > 127 ? byte - 256 : byte);
    }
    return result;
}

export function hexToBin(n: string): string {
    let bin = Number(`0x${n[0]}`).toString(2);
    for (let i = 1; i < n.length; i += 1) {
        bin += Number(`0x${n[i]}`).toString(2).padStart(4, '0');
    }
    return bin;
}
export function num2Bits(n: number, inValue: bigint): bigint[] {
    const out: bigint[] = new Array(n).fill(BigInt(0));
    let lc1: bigint = BigInt(0);
    let e2: bigint = BigInt(1);

    for (let i = 0; i < n; i++) {
        out[i] = (inValue >> BigInt(i)) & BigInt(1);

        if (out[i] !== BigInt(0) && out[i] !== BigInt(1)) {
            throw new Error('Bit value is not binary.');
        }

        lc1 += out[i] * e2;
        e2 = e2 << BigInt(1);
    }

    if (lc1 !== inValue) {
        throw new Error('Reconstructed value does not match the input.');
    }
    return out;
}