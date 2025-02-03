import path from 'path';
import { wasm as wasmTester } from 'circom_tester';
import { generateCircuitInputsCountryVerifier } from '../../../common/src/utils/generateInputs';

const testSuite = [
  {
    type: 'Greater',
    in: 1n << 64n,
  },
  {
    type: 'Equal',
    in: (1n << 64n) - 1n,
  },
  {
    type: 'Lesser',
    in: (1n << 64n) - 2n,
  },
];

describe('isNBits should work when input is', () => {
  testSuite.map(({ type, in: input }) => {
    it(type + ' than 64 bits', async () => {
      const circuit = await wasmTester(
        path.join(__dirname, `../../circuits/tests/utils/utils/isNBits${type}.circom`),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );
      const inputs = {
        in: input,
      };
      try {
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
      } catch (err) {
        console.error(err);
        throw err;
      }
    });
  });
});
