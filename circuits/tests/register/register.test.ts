import { describe } from 'mocha';
import { assert, expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { generateCircuitInputsRegister } from '../../../common/src/utils/circuits/generateInputs';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';
import { SignatureAlgorithm } from '../../../common/src/utils/types';
import { poseidon2 } from 'poseidon-lite';
import { SMT } from '@openpassport/zk-kit-smt';
import namejson from '../../../common/ofacdata/outputs/nameSMT.json';
import { getCircuitNameFromPassportData } from '../../../common/src/utils/circuits/circuitsName';
import { sigAlgs, fullSigAlgs } from './test_cases';
import { generateCommitment, generateGlue, generateNullifier, initPassportDataParsing } from '../../../common/src/utils/passports/passport';

const testSuite = process.env.FULL_TEST_SUITE === 'true' ? fullSigAlgs : sigAlgs;

testSuite.forEach(
  ({
    dgHashAlgo,
    eContentHashAlgo,
    sigAlg,
    hashFunction,
    domainParameter,
    keyLength,
    checkNullifier,
  }) => {
    describe(`Register - ${dgHashAlgo.toUpperCase()} ${eContentHashAlgo.toUpperCase()} ${hashFunction.toUpperCase()} ${sigAlg.toUpperCase()} ${domainParameter} ${keyLength}`, function () {
      this.timeout(0);
      let circuit: any;

      let passportData = genMockPassportData(
        dgHashAlgo,
        eContentHashAlgo,
        `${sigAlg}_${hashFunction}_${domainParameter}_${keyLength}` as SignatureAlgorithm,
        'FRA',
        '000101',
        '300101'
      );
      passportData = initPassportDataParsing(passportData);
      const secret = 0;
      const salt = 0;
      const attestation_id = '1';

      let name_smt = new SMT(poseidon2, true);
      name_smt.import(namejson);
      const inputs = generateCircuitInputsRegister(secret, salt, passportData);

      before(async () => {
        circuit = await wasm_tester(
          path.join(
            __dirname,
            `../../circuits/register/instances/${getCircuitNameFromPassportData(passportData)}.circom`
          ),
          {
            include: [
              'node_modules',
            ],
          }
        );
      });

      it('should compile and load the circuit', async function () {
        expect(circuit).to.not.be.undefined;
      });

      it('should calculate the witness with correct inputs', async function () {
        const w = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(w);

        const logDg1PackedHash = generateCommitment('0', '1', passportData);
        if (!checkNullifier) {
          return;
        }

        const nullifier_js = generateNullifier(passportData);
        console.log('\x1b[35m%s\x1b[0m', 'js: nullifier:', nullifier_js);
        const nullifier = (await circuit.getOutput(w, ['nullifier'])).nullifier;
        console.log('\x1b[34m%s\x1b[0m', 'circom: nullifier', nullifier);

        const commitment_js = generateCommitment(secret.toString(), attestation_id, passportData);
        console.log('\x1b[35m%s\x1b[0m', 'js: commitment:', commitment_js);
        const commitment = (await circuit.getOutput(w, ['commitment'])).commitment;
        console.log('\x1b[34m%s\x1b[0m', 'circom commitment', commitment);

        const glue_js = generateGlue(salt.toString(), passportData);
        console.log('\x1b[35m%s\x1b[0m', 'js: glue:', glue_js);
        const glue = (await circuit.getOutput(w, ['glue'])).glue;
        console.log('\x1b[34m%s\x1b[0m', 'circom: glue', glue);

        expect(commitment).to.be.equal(commitment_js);
        expect(nullifier).to.be.equal(nullifier_js);
        // expect(glue).to.be.equal(glue_js); //comment temporarily
      });

      it('should fail to calculate witness with invalid mrz', async function () {
        try {
          const invalidInputs = {
            ...inputs,
            dg1: Array(93)
              .fill(0)
              .map((byte) => BigInt(byte).toString()),
          };
          await circuit.calculateWitness(invalidInputs);
          expect.fail('Expected an error but none was thrown.');
        } catch (error) {
          expect(error.message).to.include('Assert Failed');
        }
      });

      it('should fail to calculate witness with invalid eContent', async function () {
        try {
          const invalidInputs = {
            ...inputs,
            eContent: inputs.eContent.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
          };
          await circuit.calculateWitness(invalidInputs);
          expect.fail('Expected an error but none was thrown.');
        } catch (error) {
          expect(error.message).to.include('Assert Failed');
        }
      });

      it('should fail to calculate witness with invalid signature', async function () {
        try {
          const invalidInputs = {
            ...inputs,
            signature_passport: inputs.signature_passport.map((byte: string) =>
              String((parseInt(byte, 10) + 1) % 256)
            ),
          };
          await circuit.calculateWitness(invalidInputs);
          expect.fail('Expected an error but none was thrown.');
        } catch (error) {
          expect(error.message).to.include('Assert Failed');
        }
      });
    });
  }
);
