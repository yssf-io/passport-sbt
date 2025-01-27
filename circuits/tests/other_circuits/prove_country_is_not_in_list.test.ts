import { expect } from 'chai';
import { X509Certificate } from 'crypto';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs';
import { formatMrz } from '../../../common/src/utils/passports/format';
import { formatCountriesList } from '../../../common/src/utils/circuits/formatInputs';
import { formatAndUnpackForbiddenCountriesList } from '../../../common/src/utils/circuits/formatOutputs';

describe('ProveCountryIsNotInList', function () {
  this.timeout(0);
  let circuit;

  this.beforeAll(async () => {
    const circuitPath = path.resolve(
      __dirname,
      '../../circuits/tests/utils/proveCountryIsNotInList_tester.circom'
    );
    circuit = await wasm_tester(circuitPath, {
      include: [
        'node_modules',
        './node_modules/@zk-kit/binary-merkle-root.circom/src',
        './node_modules/circomlib/circuits',
      ],
    });
  });

  describe('ProveCountryIsNotInList', async () => {
    const passportData = genMockPassportData(
      'sha256',
      'sha256',
      'rsa_sha256_65537_2048',
      'FRA',
      '000101',
      '300101'
    );
    const dg1 = formatMrz(passportData.mrz);

    it('should succeed', async () => {
      const forbiddenCountriesList = ['DZA'];

      const inputs = {
        dg1: formatInput(dg1),
        forbidden_countries_list: formatInput(formatCountriesList(forbiddenCountriesList)),
      };
      const witness = await circuit.calculateWitness(inputs);
      const forbidden_countries_list_packed = await circuit.getOutput(witness, [
        'forbidden_countries_list_packed[1]',
      ]);
      console.log(
        '\x1b[34m%s\x1b[0m',
        'forbidden_countries_list_packed',
        formatAndUnpackForbiddenCountriesList(forbidden_countries_list_packed)
      );
    });

    it('should faild - country FRA is in the list', async () => {
      const forbiddenCountriesList = ['FRA', 'DZA'];
      try {
        const inputs = {
          dg1: formatInput(dg1),
          forbidden_countries_list: formatInput(formatCountriesList(forbiddenCountriesList)),
        };
        const witness = await circuit.calculateWitness(inputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });
  });
});
