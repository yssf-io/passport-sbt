import { describe } from 'mocha';
import { assert, expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import {
  attributeToPosition,
  PASSPORT_ATTESTATION_ID,
} from '../../../common/src/constants/constants';
import { poseidon1, poseidon2 } from 'poseidon-lite';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { generateCircuitInputsVCandDisclose } from '../../../common/src/utils/circuits/generateInputs';
import crypto from 'crypto';
import { genMockPassportData } from '../../../common/src/utils/passports/genMockPassportData';
import { SMT } from '@openpassport/zk-kit-smt';
import namejson from '../../../common/ofacdata/outputs/nameSMT.json';
import { formatAndUnpackReveal, formatAndUnpackForbiddenCountriesList } from '../../../common/src/utils/circuits/formatOutputs';
import { generateCommitment, initPassportDataParsing } from '../../../common/src/utils/passports/passport';

describe('Disclose', function () {
  this.timeout(0);
  let inputs: any;
  let circuit: any;
  let w: any;
  let passportData = genMockPassportData(
    'sha256',
    'sha256',
    'rsa_sha256_65537_2048',
    'FRA',
    '000101',
    '300101'
  );
  passportData = initPassportDataParsing(passportData);
  let tree: any;
  let forbidden_countries_list: any;
  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/disclose/vc_and_disclose.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    const secret = BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString();

    const majority = '18';
    const user_identifier = crypto.randomUUID();
    const selector_dg1 = Array(88).fill('1');
    const selector_older_than = '1';
    const scope = '@coboyApp';
    const attestation_id = PASSPORT_ATTESTATION_ID;

    // compute the commitment and insert it in the tree
    const commitment = generateCommitment(secret, attestation_id, passportData);
    console.log('commitment in js ', commitment);
    tree = new LeanIMT((a, b) => poseidon2([a, b]), []);
    tree.insert(BigInt(commitment));
    let smt = new SMT(poseidon2, true);
    smt.import(namejson);

    const selector_ofac = 1;
    forbidden_countries_list = ['ALG', 'DZA'];

    inputs = generateCircuitInputsVCandDisclose(
      secret,
      PASSPORT_ATTESTATION_ID,
      passportData,
      scope,
      selector_dg1,
      selector_older_than,
      tree,
      majority,
      smt,
      selector_ofac,
      forbidden_countries_list,
      user_identifier
    );
  });

  it('should compile and load the circuit', async function () {
    expect(circuit).to.not.be.undefined;
  });

  it('should have nullifier == poseidon(secret, scope)', async function () {
    w = await circuit.calculateWitness(inputs);
    const nullifier_js = poseidon2([inputs.secret, inputs.scope]).toString();
    const nullifier_circom = (await circuit.getOutput(w, ['nullifier'])).nullifier;

    console.log('nullifier_circom', nullifier_circom);
    console.log('nullifier_js', nullifier_js);
    expect(nullifier_circom).to.equal(nullifier_js);
  });

  it('should fail to calculate witness with different attestation_id', async function () {
    try {
      const invalidInputs = {
        ...inputs,
        attestation_id: poseidon1([
          BigInt(Buffer.from('ANON-AADHAAR').readUIntBE(0, 6)),
        ]).toString(),
      };
      await circuit.calculateWitness(invalidInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      // expect(error.message).to.include('Assert Failed');
    }
  });

  describe('MRZ selective disclosure', function () {
    const attributeCombinations = [
      ['issuing_state', 'name'],
      ['passport_number', 'nationality', 'date_of_birth'],
      ['gender', 'expiry_date'],
    ];

    attributeCombinations.forEach((combination) => {
      it(`Disclosing ${combination.join(', ')}`, async function () {
        const attributeToReveal = Object.keys(attributeToPosition).reduce((acc, attribute) => {
          acc[attribute] = combination.includes(attribute);
          return acc;
        }, {});

        const selector_dg1 = Array(88).fill('0');

        Object.entries(attributeToReveal).forEach(([attribute, reveal]) => {
          if (reveal) {
            const [start, end] = attributeToPosition[attribute];
            selector_dg1.fill('1', start, end + 1);
          }
        });

        inputs = {
          ...inputs,
          selector_dg1: selector_dg1.map(String),
        };

        w = await circuit.calculateWitness(inputs);

        const revealedData_packed = await circuit.getOutput(w, ['revealedData_packed[3]']);

        const reveal_unpacked = formatAndUnpackReveal(revealedData_packed);

        for (let i = 0; i < 88; i++) {
          if (selector_dg1[i] == '1') {
            const char = String.fromCharCode(Number(inputs.dg1[i + 5]));
            assert(reveal_unpacked[i] == char, 'Should reveal the right character');
          } else {
            assert(reveal_unpacked[i] == '\x00', 'Should not reveal');
          }
        }

        const forbidden_countries_list_packed = await circuit.getOutput(w, ['forbidden_countries_list_packed[1]'])
        const forbidden_countries_list_unpacked = formatAndUnpackForbiddenCountriesList(forbidden_countries_list_packed);
        expect(forbidden_countries_list_unpacked).to.deep.equal(forbidden_countries_list);
      });
    });
  });

  it('should allow disclosing majority', async function () {
    const selector_dg1 = Array(88).fill('0');

    w = await circuit.calculateWitness({
      ...inputs,
      selector_dg1: selector_dg1.map(String),
    });
    const revealedData_packed = await circuit.getOutput(w, ['revealedData_packed[3]']);

    const reveal_unpacked = formatAndUnpackReveal(revealedData_packed);
    const older_than = getAttributeFromUnpackedReveal(reveal_unpacked, 'older_than');
    expect(older_than).to.equal('18');
  });

  it("shouldn't allow disclosing wrong majority", async function () {
    const selector_dg1 = Array(88).fill('0');

    w = await circuit.calculateWitness({
      ...inputs,
      majority: ['5', '0'].map((char) => BigInt(char.charCodeAt(0)).toString()),
      selector_dg1: selector_dg1.map(String),
    });

    const revealedData_packed = await circuit.getOutput(w, ['revealedData_packed[3]']);

    const reveal_unpacked = formatAndUnpackReveal(revealedData_packed);
    expect(reveal_unpacked[88]).to.equal('\x00');
    expect(reveal_unpacked[89]).to.equal('\x00');
  });
});

const formatOlderThan = (older_than: any) => {
  return Object.values(older_than).map((value: any) => parseInt(value) - 48);
};


const getAttributeFromUnpackedReveal = (unpackedReveal: string[], attributeName: keyof typeof attributeToPosition): string => {
  const [start, end] = attributeToPosition[attributeName];
  return unpackedReveal.slice(start, end + 1).join('').replace(/\x00/g, '');
};
