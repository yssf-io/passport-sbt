import { expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs';
import { customHasher } from '../../../common/src/utils/hash';

describe('CustomHasher', function () {
  this.timeout(0);
  let circuit;

  this.beforeAll(async () => {
    const circuitPath = path.resolve(
      __dirname,
      '../../circuits/tests/utils/customHasher_tester.circom'
    );
    circuit = await wasm_tester(circuitPath, {
      include: [
        'node_modules',
        './node_modules/@zk-kit/binary-merkle-root.circom/src',
        './node_modules/circomlib/circuits',
      ],
    });
  });

  describe('custom hasher', async () => {
    const randomNumbers = Array(16)
      .fill(0)
      .map(() => {
        const maxVal = BigInt(2) ** BigInt(250);
        const randomVal =
          BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) *
          BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
        return (randomVal % maxVal).toString();
      });
    const inputs = { in: formatInput(randomNumbers) };

    it('customHasher output should be the same between circom and js implementation', async () => {
      const witness = await circuit.calculateWitness(inputs, true);
      const hashValueCircom = (await circuit.getOutput(witness, ['out'])).out;
      console.log('\x1b[34m', 'hashValueCircom: ', hashValueCircom, '\x1b[0m');
      const hashValueJs = customHasher(randomNumbers);
      console.log('\x1b[34m', 'hashValueJs: ', hashValueJs, '\x1b[0m');
      expect(BigInt(hashValueCircom).toString()).to.equal(BigInt(hashValueJs).toString());
    });
  });
});
