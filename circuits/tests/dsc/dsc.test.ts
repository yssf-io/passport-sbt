import { assert, expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { generateCircuitInputsDSC } from '../../../common/src/utils/circuits/generateInputs';

import { fullSigAlgs, sigAlgs } from './test_cases';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';
import { SignatureAlgorithm } from '../../../common/src/utils/types';
import { initPassportDataParsing } from '../../../common/src/utils/passports/passport';
import { getCircuitNameFromPassportData } from '../../../common/src/utils/circuits/circuitsName';

const testSuite = process.env.FULL_TEST_SUITE === 'true' ? fullSigAlgs : sigAlgs;

testSuite.forEach(({
  sigAlg,
  hashFunction,
  domainParameter,
  keyLength,
}) => {

  let passportData = genMockPassportData(
    hashFunction,
    hashFunction,
    `${sigAlg}_${hashFunction}_${domainParameter}_${keyLength}` as SignatureAlgorithm,
    'FRA',
    '000101',
    '300101'
  );
  passportData = initPassportDataParsing(passportData);
  const passportMetadata = passportData.passportMetadata;

  describe(`DSC chain certificate - ${passportMetadata.cscaHashFunction.toUpperCase()} ${passportMetadata.cscaSignatureAlgorithm.toUpperCase()} ${passportMetadata.cscaCurveOrExponent.toUpperCase()} ${passportData.csca_parsed.publicKeyDetails.bits}`, function () {
    this.timeout(0); // Disable timeout
    let circuit;

    // Mock certificates based on signature algorithm and hash function
    let passportData = genMockPassportData(
      hashFunction,
      hashFunction,
      `${sigAlg}_${hashFunction}_${domainParameter}_${keyLength}` as SignatureAlgorithm,
      'FRA',
      '000101',
      '300101'
    );
    passportData = initPassportDataParsing(passportData);

    const inputs = generateCircuitInputsDSC(
      passportData.dsc,
      true
    );

    before(async () => {
      circuit = await wasm_tester(
        path.join(
          __dirname,
          `../../circuits/dsc/instances/${getCircuitNameFromPassportData(passportData, 'dsc')}.circom`
        ),
        {
          include: [
            'node_modules',
            './node_modules/@zk-kit/binary-merkle-root.circom/src',
            './node_modules/circomlib/circuits',
          ],
        }
      );
    });

    it('should compute a valid witness', async () => {
      const witness = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);
      console.log('\x1b[34m%s\x1b[0m', 'witness generated ', sigAlg);
      const dsc_tree_leaf = (await circuit.getOutput(witness, ['dsc_tree_leaf']))
        .dsc_tree_leaf;
      console.log('\x1b[34m%s\x1b[0m', 'dsc_tree_leaf: ', dsc_tree_leaf);
    });
  });
});
