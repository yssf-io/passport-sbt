import dotenv from 'dotenv';
import { assert, expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { generateCircuitInputsDSC } from '../../../common/src/utils/circuits/generateInputs';

import { fullSigAlgs, sigAlgs } from './test_cases';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';
import { SignatureAlgorithm } from '../../../common/src/utils/types';
import { initPassportDataParsing } from '../../../common/src/utils/passports/passport';
import { getCircuitNameFromPassportData } from '../../../common/src/utils/circuits/circuitsName';
import { getLeafDscTreeFromParsedDsc } from '../../../common/src/utils/trees';
import { parseCertificateSimple } from '../../../common/src/utils/certificate_parsing/parseCertificateSimple';
import { parseDscCertificateData } from '../../../common/src/utils/passports/passport_parsing/parseDscCertificateData';
dotenv.config();

const testSuite = process.env.FULL_TEST_SUITE === 'true' ? fullSigAlgs : sigAlgs;

testSuite.forEach(({ sigAlg, hashFunction, domainParameter, keyLength }) => {
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

  describe(`DSC chain certificate - ${passportMetadata.cscaHashFunction.toUpperCase()} ${passportMetadata.cscaSignatureAlgorithm.toUpperCase()} ${passportMetadata.cscaCurveOrExponent.toUpperCase()} ${
    passportData.csca_parsed.publicKeyDetails.bits
  }`, function () {
    this.timeout(0); // Disable timeout
    let circuit;

    const inputs = generateCircuitInputsDSC(passportData.dsc, true);

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

    it('should compile and load the circuit', async function () {
      expect(circuit).to.not.be.undefined;
    });

    it('should compute a valid witness and output the right dsc_tree_leaf', async () => {
      const witness = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);
      console.log('\x1b[34m%s\x1b[0m', 'witness generated ', sigAlg);

      const dsc_tree_leaf = (await circuit.getOutput(witness, ['dsc_tree_leaf'])).dsc_tree_leaf;
      console.log('\x1b[34m%s\x1b[0m', 'circom: dsc_tree_leaf: ', dsc_tree_leaf);
      expect(dsc_tree_leaf).to.be.a('string');

      const dsc_tree_leaf_js = getLeafDscTreeFromParsedDsc(passportData.dsc_parsed);
      console.log('\x1b[34m%s\x1b[0m', 'js: dsc_tree_leaf: ', dsc_tree_leaf_js);
      expect(dsc_tree_leaf).to.be.equal(dsc_tree_leaf_js);
    });

    it('should fail if raw_csca_actual_length higher than the correct length', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.raw_csca_actual_length = (
          Number(tamperedInputs.raw_csca_actual_length) + 1
        ).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if raw_csca_actual_length lower than the correct length', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.raw_csca_actual_length = (
          Number(tamperedInputs.raw_csca_actual_length) - 1
        ).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if raw_csca[raw_csca_actual_length - 1] is not 255', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.raw_csca[Number(tamperedInputs.raw_csca_actual_length) - 1] = '254';

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if a byte of raw_csca after raw_csca_actual_length is not 0', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.raw_csca[Number(tamperedInputs.raw_csca_actual_length)] = '1';

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if csca_pubKey_actual_size is lower than the minimum key length', async () => {
      try {
        const dscParsed = parseCertificateSimple(passportData.dsc);
        const dscMetadata = parseDscCertificateData(dscParsed);
        const cscaParsed = parseCertificateSimple(dscMetadata.csca);

        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        if (cscaParsed.signatureAlgorithm === 'rsa') {
          tamperedInputs.csca_pubKey_actual_size = (256 - 1).toString(); // 256 is the minimum key length for RSA
        } else {
          // for ecdsa and rsapss, the minimum key length is fixed for each circuit
          tamperedInputs.csca_pubKey_actual_size = (
            Number(tamperedInputs.csca_pubKey_actual_size) - 1
          ).toString();
        }

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if csca_pubKey_offset + csca_pubKey_actual_size > raw_csca_actual_length', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.csca_pubKey_offset = (
          Number(tamperedInputs.raw_csca_actual_length) -
          Number(tamperedInputs.csca_pubKey_actual_size) +
          1
        ).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if csca_pubKey_actual_size is larger than the key in certificate', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.csca_pubKey_actual_size = (
          Number(tamperedInputs.csca_pubKey_actual_size) + 8
        ).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if csca_pubKey is invalid', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.csca_pubKey[0] = BigInt(
          Number(tamperedInputs.csca_pubKey[0]) + 1
        ).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail to compute a witness with an invalid merkle_root', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.merkle_root = BigInt(Number(tamperedInputs.merkle_root) + 1).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail to compute a witness with an invalid path', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.path[0] = BigInt(Number(tamperedInputs.path[0]) + 1).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail to compute a witness with an invalid merkle proof', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.siblings[0] = BigInt(Number(tamperedInputs.siblings[0]) + 1).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail to compute a witness with a dsc that is not padded with 0s after the sha padding', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.raw_dsc[tamperedInputs.raw_dsc.length - 1] = (
          Number(tamperedInputs.raw_dsc[tamperedInputs.raw_dsc.length - 1]) + 1
        ).toString();

        console.log(JSON.stringify(Array.from(tamperedInputs.raw_dsc)));

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    [64, -64, 1, -1].forEach((delta) => {
      it(`should fail to compute a witness when raw_dsc_padded_length is adjusted by ${delta}`, async () => {
        try {
          const tamperedInputs = JSON.parse(JSON.stringify(inputs));
          tamperedInputs.raw_dsc_padded_length = (
            Number(tamperedInputs.raw_dsc_padded_length) + delta
          ).toString();

          await circuit.calculateWitness(tamperedInputs);
          expect.fail('Expected an error but none was thrown.');
        } catch (error) {
          expect(error.message).to.include('Assert Failed');
        }
      });
    });

    it('should fail to compute a witness with an invalid signature', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        tamperedInputs.signature[0] = BigInt(Number(tamperedInputs.signature[0]) + 1).toString();

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('should fail if ECDSA public key coordinates are swapped', async () => {
      try {
        const tamperedInputs = JSON.parse(JSON.stringify(inputs));
        const halfLength = tamperedInputs.csca_pubKey.length / 2;
        const firstHalf = tamperedInputs.csca_pubKey.slice(0, halfLength).reverse();
        const secondHalf = tamperedInputs.csca_pubKey.slice(halfLength).reverse();
        tamperedInputs.csca_pubKey = [...firstHalf, ...secondHalf];

        await circuit.calculateWitness(tamperedInputs);
        expect.fail('Expected an error but none was thrown.');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });
  });
});
