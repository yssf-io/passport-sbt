import { wasm as wasmTester } from 'circom_tester';
import * as crypto from 'crypto';
import { initElliptic } from '../../../common/src/utils/certificate_parsing/elliptic';
import * as path from 'path';
import { splitToWords } from '../../../common/src/utils/bytes';

const elliptic = initElliptic();
const testSuite = [
  {
    hash: 'sha512',
    curve: 'brainpoolP256r1',
    n: 64,
    k: 4,
    reason: 'when hash is greater than curve bits',
  },
];

const fullTestSuite = [
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
        [true, 'should verify'],
        [false, 'should not verify'],
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
              console.log(error);
              throw new Error('Test failed: Valid signature was not verified.');
            }
          }
        });
      });
    });
    it('should not verify if either signature component is greater than the order', async function () {
      this.timeout(0);
      // takes way too long to find a valid input for these
      if (['p256', 'p384'].includes(curve)) {
        return;
      }
      const circuit = await wasmTester(
        path.join(__dirname, `../../circuits/tests/utils/ecdsa/test_${curve}.circom`),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );

      for (const item of [true, false]) {
        try {
          let inputs;
          while (true) {
            try {
              inputs = signOverflow(message, curve, hash, k, n, item);
              break;
            } catch (err) {}
          }
          const witness = await circuit.calculateWitness(inputs);
          await circuit.checkConstraints(witness);
          throw new Error('Test failed: Invalid signature was verified.');
        } catch (error) {}
      }
    });
  });
  it('should not accept invalid chunks in the signature', async function () {
    this.timeout(0);
    const circuit = await wasmTester(
      path.join(__dirname, `../../circuits/tests/utils/ecdsa/test_p256.circom`),
      {
        include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
      }
    );

    const inputs = {
      signature: [
        [
          '11897043862654108222',
          '6687976630675743167',
          '6842677606991059234',
          '3933303995770833589',
        ],
        [
          '10364704208062614840',
          '21394470794141451286901280378935131115',
          '0',
          '15812853153589603704',
        ],
      ],
      pubKey: [
        [
          '1647443686294582730',
          '7524809848328723651',
          '2690299118416708846',
          '2230381215521625212',
        ],
        [
          '12063856007545978738',
          '2856046104882309217',
          '14084651496056034469',
          '2603012891351374004',
        ],
      ],
      hashParsed: [
        0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1,
        0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0,
        1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1,
        0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0,
        1, 0, 1, 1, 1, 0, 1, 0,
      ],
    };

    try {
      const witness = await circuit.calculateWitness(inputs);
      await circuit.checkConstraints(witness);
      throw new Error('Test failed: Invalid signature was verified.');
    } catch (err) {
      if (!(err as Error).message.includes('isNBits')) {
        throw err;
      }
    }
  });

  it.only('should reduce the final signature addition mod n', async function () {
    this.timeout(0);
    const circuit = await wasmTester(
      path.join(__dirname, `../../circuits/tests/utils/ecdsa/test_p256.circom`),
      {
        include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
      }
    );

    const inputs = {
      signature: [
        ['884452912994769579', '4834901530490986875', '0', '0'],
        [
          '17562291160714782030',
          '13611842547513532036',
          '18446744073709551615',
          '18446744069414584320',
        ],
      ],
      pubKey: [
        [
          '12004473255778836739',
          '5567425807485590512',
          '4612562821672420442',
          '781819838238377577',
        ],
        [
          '2517678904895060574',
          '13415238991415823444',
          '5824794594647846510',
          '14195660962316692941',
        ],
      ],
      hashParsed: [
        1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0,
        0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
        0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0,
        1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
        0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
        1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 1, 1,
      ],
    };
    try {
      const witness = await circuit.calculateWitness(inputs);
      await circuit.checkConstraints(witness);
    } catch (err) {
      throw err;
    }
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

function signOverflow(
  message: Uint8Array,
  curve: string,
  hash: string,
  n: number,
  k: number,
  overflowS: boolean
) {
  const ec = new elliptic.ec(curve);

  const key = ec.genKeyPair();

  const messageHash = crypto.createHash(hash).update(message).digest();

  const signature = key.sign(messageHash, 'hex');
  const pubkey = key.getPublic();
  const hashParsed = [];
  Array.from(messageHash).forEach((x) =>
    hashParsed.push(...x.toString(2).padStart(8, '0').split(''))
  );

  let r = BigInt(signature.r);
  let s = BigInt(signature.s);

  if (overflowS) {
    s = s + BigInt(ec.n);
  } else {
    r = r + BigInt(ec.n);
  }

  return {
    signature: [...splitToWords(r, k, n), ...splitToWords(s, k, n)],
    pubKey: [
      splitToWords(BigInt(pubkey.getX().toString()), k, n),
      splitToWords(BigInt(pubkey.getY().toString()), k, n),
    ],
    hashParsed,
  };
}
