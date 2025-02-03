import { wasm as wasmTester } from 'circom_tester';
import { describe, it, before } from 'mocha';
import path from 'path';
import fs from 'fs';
import { hexToDecimal } from '../../../common/src/utils/bytes';
import { splitToWords } from '../../../common/src/utils/bytes';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs';
import { expect } from 'chai';

describe('Circuit Test', function () {
  this.timeout(0);

  const n_and_k = [
    { n: 120, k: 35, keyLength: 2048, isEcdsa: false },
    { n: 120, k: 35, keyLength: 3072, isEcdsa: false },
    { n: 120, k: 35, keyLength: 4096, isEcdsa: false },
    { n: 32, k: 7, keyLength: 224, isEcdsa: true },
    { n: 64, k: 4, keyLength: 256, isEcdsa: true },
    { n: 64, k: 6, keyLength: 384, isEcdsa: true },
    { n: 64, k: 8, keyLength: 512, isEcdsa: true },
  ];
  const is_ci_cd = true;
  const num_tests = is_ci_cd ? 100 : 1000;

  n_and_k.forEach(({ n, k, keyLength, isEcdsa }) => {
    describe(`n=${n},k=${k}`, function () {
      let circuit;
      this.timeout(0);

      before(async function () {
        circuit = await wasmTester(
          path.join(__dirname, `../../circuits/tests/others/test_glue_${n}_${k}.circom`),
          {
            include: [
              'node_modules',
              './node_modules/@zk-kit/binary-merkle-root.circom/src',
              './node_modules/circomlib/circuits',
            ],
          }
        );
      });

      for (let i = 0; i < num_tests; i++) {
        let pubkey_dsc;
        let pubkey_dsc_padded;
        if (isEcdsa) {
          // Generate random binary strings of length keyLength
          const xBinary = Array.from({ length: keyLength }, () =>
            Math.random() < 0.5 ? '1' : '0'
          ).join('');
          const yBinary = Array.from({ length: keyLength }, () =>
            Math.random() < 0.5 ? '1' : '0'
          ).join('');

          const x = BigInt('0b' + xBinary);
          const y = BigInt('0b' + yBinary);

          const pubKey_dsc_x = splitToWords(x, n, k);
          const pubKey_dsc_y = splitToWords(y, n, k);
          pubkey_dsc = [...pubKey_dsc_x, ...pubKey_dsc_y];
          const fullPubKey = xBinary.concat(yBinary);
          pubkey_dsc_padded = splitToWords(BigInt('0b' + fullPubKey), 8, 525);
        } else {
          // Generate random binary string of length keyLength
          const modulusBinary = Array.from({ length: keyLength }, () =>
            Math.random() < 0.5 ? '1' : '0'
          ).join('');
          const modulus = BigInt('0b' + modulusBinary);

          pubkey_dsc = splitToWords(modulus, n, k);
          pubkey_dsc_padded = formatInput(splitToWords(modulus, 8, 525));
        }
        const salt = '0';
        const pubKey_csca_hash = '0';
        it(`i=${i}`, async function () {
          await runTest(circuit, pubkey_dsc, pubkey_dsc_padded, salt, pubKey_csca_hash);
        });
      }

      async function runTest(circuit, pubkey_dsc, pubkey_dsc_padded, salt, pubKey_csca_hash) {
        const witness = await circuit.calculateWitness({
          pubKey_dsc: pubkey_dsc,
          pubkey_dsc_padded,
          salt,
          pubKey_csca_hash,
        });
        const register_hash = (await circuit.getOutput(witness, ['register_hash'])).register_hash;
        const dsc_hash = (await circuit.getOutput(witness, ['dsc_hash'])).dsc_hash;

        if (register_hash !== dsc_hash) {
          console.log('\x1b[31m%s\x1b[0m', 'TEST FAILED');
          logTestFailure(
            n,
            k,
            keyLength,
            isEcdsa,
            pubkey_dsc,
            pubkey_dsc_padded,
            register_hash,
            dsc_hash
          );
        }
        expect(register_hash).to.be.equal(dsc_hash);
      }
    });
  });
});

function logTestFailure(
  n,
  k,
  keyLength,
  isEcdsa,
  pubkey_dsc,
  pubkey_dsc_padded,
  register_hash,
  dsc_hash
) {
  const logsDir = path.join(__dirname, '../../tests/logs/glue');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  // Create timestamp for filename
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const logFile = path.join(logsDir, `test_failure_${timestamp}.log`);

  // Format the log content
  const logContent = `Test Failure Log - ${timestamp}
----------------------------------------
Test Configuration:
n: ${n}
k: ${k}
keyLength: ${keyLength}
isEcdsa: ${isEcdsa}

Test Values:
pubkey_dsc:
${JSON.stringify(pubkey_dsc, null, 2)}

pubkey_dsc_padded:
${JSON.stringify(pubkey_dsc_padded, null, 2)}

Hash Values:
register_hash: ${register_hash}
dsc_hash: ${dsc_hash}
----------------------------------------
`;

  // Write to log file
  fs.writeFileSync(logFile, logContent);
}
