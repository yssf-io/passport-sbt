import { wasm as wasmTester } from 'circom_tester';
import * as crypto from 'crypto';
import { initElliptic } from '../../../common/src/utils/certificate_parsing/elliptic';
import * as path from 'path';
import { splitToWords } from '../../../common/src/utils/bytes';

const elliptic = initElliptic();

const testSuite = [
  {
    hash: 'sha1',
    curve: 'brainpoolP224r1',
    n: 32,
    k: 7,
    reason: 'when hash is lesser than curve bits',
  },
  {
    hash: 'sha512',
    curve: 'brainpoolP256r1',
    n: 64,
    k: 4,
    reason: 'when hash is greater than curve bits',
  },
  {
    hash: 'sha384',
    curve: 'brainpoolP384r1',
    n: 64,
    k: 6,
    reason: 'when hash bits are the same as curve bits',
  },
  {
    hash: 'sha512',
    curve: 'brainpoolP512r1',
    n: 64,
    k: 8,
    reason: 'when hash bits are the same as curve bits',
  },
  {
    hash: 'sha256',
    curve: 'p256',
    n: 64,
    k: 4,
    reason: 'when hash bits are the same as curve bits',
  },
  {
    hash: 'sha384',
    curve: 'p384',
    n: 64,
    k: 6,
    reason: 'when hash bits are the same as curve bits',
  },
  {
    hash: 'sha512',
    curve: 'p521',
    n: 66,
    k: 8,
    reason: 'when hash bits are less than the curve bits',
  },
];

describe('ecdsa', () => {
  testSuite.forEach(({ hash, curve, n, k, reason }) => {
    const message = crypto.randomBytes(32);

    (
      [
        [true, 'should verify correctly'],
        [false, 'should not verify correctly'],
      ] as [boolean, string][]
    ).forEach(([shouldVerify, shouldVerifyReason]) => {
      describe(shouldVerifyReason, function () {
        this.timeout(0);
        const inputs = sign(message, curve, hash, k, n);
        if (!shouldVerify) {
          inputs.hashParsed.map((x) => 0);
        }

        it(reason, async () => {
          const circuit = await wasmTester(
            path.join(__dirname, `../../circuits/tests/utils/ecdsa/test_${curve}.circom`),
            {
              include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
            }
          );

          try {
            const witness = await circuit.calculateWitness(inputs);
            await circuit.checkConstraints(witness);
            if (!shouldVerify) {
              throw new Error('Test failed: Invalid signature was verified.');
            }
          } catch (error) {
            if (shouldVerify) {
              throw new Error('Test failed: Valid signature was not verified.');
            }
          }
        });
      });
    });
  });
});

function sign(message: Uint8Array, curve: string, hash: string, n: number, k: number) {
  const ec = new elliptic.ec(curve);

  const key = ec.genKeyPair();

  const messageHash = crypto.createHash(hash).update(message).digest();

  const signature = key.sign(messageHash, 'hex');
  const pubkey = key.getPublic();
  const hashParsed = [];
  Array.from(messageHash).forEach((x) =>
    hashParsed.push(...x.toString(2).padStart(8, '0').split(''))
  );

  return {
    signature: [
      ...splitToWords(BigInt(signature.r), k, n),
      ...splitToWords(BigInt(signature.s), k, n),
    ],
    pubKey: [
      splitToWords(BigInt(pubkey.getX().toString()), k, n),
      splitToWords(BigInt(pubkey.getY().toString()), k, n),
    ],
    hashParsed,
  };
}
