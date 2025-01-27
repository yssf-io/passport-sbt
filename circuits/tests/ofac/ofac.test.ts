import { expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { generateCircuitInputsOfac } from '../../../common/src/utils/circuits/generateInputs';
import { SMT } from '@openpassport/zk-kit-smt';
import { poseidon2 } from 'poseidon-lite';
import passportNojson from '../../../common/ofacdata/outputs/passportNoSMT.json';
import nameDobjson from '../../../common/ofacdata/outputs/nameDobSMT.json';
import namejson from '../../../common/ofacdata/outputs/nameSMT.json';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';

let circuit: any;

// Mock passport added in ofac list to test circuits
const passportData = genMockPassportData(
  'sha256',
  'sha256',
  'rsa_sha256_65537_2048',
  'FRA',
  '040211',
  '300101'
);
// Mock passport not added in ofac list to test circuits
const passportDataInOfac = genMockPassportData(
  'sha256',
  'sha256',
  'rsa_sha256_65537_2048',
  'FRA',
  '541007',
  '300101',
  '98lh90556',
  'HENAO MONTOYA',
  'ARCANGEL DE JESUS'
);

// POSSIBLE TESTS (for each of 3 circuits):
// 0. Cicuits compiles and loads
// 1. Valid proof   : Correct path and corresponding closest leaf AND leaf != pasport_hash ; Valid prove of non-membership
// 2. Invalid proof : Correct path and corresponding closest leaf AND leaf == pasport_hash ; Valid prove of membership ; Hence non-membership proof would fail
// 3. Invalid proof : Correct path but wrong corresponding siblings ; fails due to calculatedRoot != smt_root

// Level 3: Passport number match in OfacList
describe('OFAC - Passport number match', function () {
  this.timeout(0);
  let passno_smt = new SMT(poseidon2, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(
        __dirname,
        '../../circuits/ofac/../../circuits/tests/ofac/ofac_passport_number_tester.circom'
      ),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    passno_smt.import(passportNojson);
    const proofLevel = 3;
    memSmtInputs = generateCircuitInputsOfac(passportDataInOfac, passno_smt, proofLevel);

    nonMemSmtInputs = generateCircuitInputsOfac(passportData, passno_smt, proofLevel);
  });

  // Compile circuit
  it('should compile and load the circuit, level 3', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Correct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors, all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('1');
  });

  // Correct siblings but membership proof: Fail at line 43 assertion
  it('should pass - passport is in ofac list, level 3', async function () {
    let w = await circuit.calculateWitness(memSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });

  // Give wrong closest leaf but correct siblings array : Fail of SMT Verification
  it('should pass - wrong merkleroot, level 3', async function () {
    const wrongInputs = {
      ...nonMemSmtInputs,
      smt_leaf_key: BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString(),
    };
    let w = await circuit.calculateWitness(wrongInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });
});

// Level 2: NameDob match in OfacList
describe('OFAC - Name and DOB match', function () {
  this.timeout(0);
  let namedob_smt = new SMT(poseidon2, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/tests/ofac/ofac_name_dob_tester.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    namedob_smt.import(nameDobjson);
    const proofLevel = 2;
    memSmtInputs = generateCircuitInputsOfac(
      // proof of membership
      passportDataInOfac,
      namedob_smt,
      proofLevel
    );

    nonMemSmtInputs = generateCircuitInputsOfac(
      // proof of non-membership
      passportData,
      namedob_smt,
      proofLevel
    );
  });

  // Compile circuit
  it('should compile and load the circuit, level 2', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Correct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors, all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('1');
  });

  // Correct siblings but membership proof : Fail at line 54 assertion
  it('should pass - passport is in ofac list, level 2', async function () {
    let w = await circuit.calculateWitness(memSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });

  // Give wrong closest leaf but correct siblings array
  it('should pass - wrong merkleroot, level 2', async function () {
    const wrongInputs = {
      ...nonMemSmtInputs,
      smt_leaf_key: BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString(),
    };

    let w = await circuit.calculateWitness(wrongInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });
});

// Level 1: Name match in OfacList
describe('OFAC - Name match', function () {
  this.timeout(0);
  let name_smt = new SMT(poseidon2, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/tests/ofac/ofac_name_tester.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    name_smt.import(namejson);
    const proofLevel = 1;
    memSmtInputs = generateCircuitInputsOfac(
      // proof of membership
      passportDataInOfac,
      name_smt,
      proofLevel
    );

    nonMemSmtInputs = generateCircuitInputsOfac(
      // proof of non-membership
      passportData,
      name_smt,
      proofLevel
    );
  });

  // Compile circuit
  it('should compile and load the circuit, level 1', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Correct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors, all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('1');
  });

  // Correct siblings but membership proof : Fail at line 46 assertion
  it('should pass - passport is in ofac list, level 1', async function () {
    let w = await circuit.calculateWitness(memSmtInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });

  // Give wrong closest leaf but correct siblings array
  it('should pass - wrong merkleroot, level 1', async function () {
    const wrongInputs = {
      ...nonMemSmtInputs,
      smt_leaf_key: BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString(),
    };
    let w = await circuit.calculateWitness(wrongInputs);
    const ofacCheckResult = (await circuit.getOutput(w, ['ofacCheckResult'])).ofacCheckResult;
    expect(ofacCheckResult).to.equal('0');
  });
});
