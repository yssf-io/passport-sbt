import {
  PROVE_RSA_NULLIFIER_INDEX,
  PROVE_RSA_REVEALED_DATA_PACKED_INDEX,
  PROVE_RSA_OLDER_THAN_INDEX,
  PROVE_RSA_PUBKEY_DISCLOSED_INDEX,
  PROVE_RSA_FORBIDDEN_COUNTRIES_LIST_PACKED_DISCLOSED_INDEX,
  PROVE_RSA_OFAC_RESULT_INDEX,
  PROVE_RSA_COMMITMENT_INDEX,
  PROVE_RSA_BLINDED_DSC_COMMITMENT_INDEX,
  PROVE_RSA_CURRENT_DATE_INDEX,
  PROVE_RSA_USER_IDENTIFIER_INDEX,
  PROVE_RSA_SCOPE_INDEX,
  DSC_BLINDED_DSC_COMMITMENT_INDEX,
} from '../../../constants/contractConstants';
import { Proof } from '../../types';

export function generateMockRSAProveVerifierInputs({
  nullifier = '1',
  revealedData_packed = ['2', '3', '4'],
  older_than = ['49', '56'],
  pubkey_disclosed = [
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
  ],
  forbidden_contries_list_packed_disclose = ['8', '9'],
  ofac_result = '10',
  commitment = '11',
  blinded_dsc_commitment = '12',
  current_date = new Date(),
  user_identifier = '13',
  scope = '14',
}: {
  nullifier?: string;
  revealedData_packed?: string[];
  older_than?: string[];
  pubkey_disclosed?: string[];
  forbidden_contries_list_packed_disclose?: string[];
  ofac_result?: string;
  commitment?: string;
  blinded_dsc_commitment?: string;
  current_date?: Date;
  user_identifier?: string;
  scope?: string;
}): Proof {
  let pub_signals: string[] = [];

  pub_signals[PROVE_RSA_NULLIFIER_INDEX] = nullifier;
  pub_signals.splice(PROVE_RSA_REVEALED_DATA_PACKED_INDEX, 0, ...revealedData_packed);
  pub_signals.splice(PROVE_RSA_OLDER_THAN_INDEX, 0, ...older_than);
  pub_signals.splice(PROVE_RSA_PUBKEY_DISCLOSED_INDEX, 0, ...pubkey_disclosed);
  pub_signals.splice(
    PROVE_RSA_FORBIDDEN_COUNTRIES_LIST_PACKED_DISCLOSED_INDEX,
    0,
    ...forbidden_contries_list_packed_disclose
  );
  pub_signals[PROVE_RSA_OFAC_RESULT_INDEX] = ofac_result;
  pub_signals[PROVE_RSA_COMMITMENT_INDEX] = commitment;
  pub_signals[PROVE_RSA_BLINDED_DSC_COMMITMENT_INDEX] = blinded_dsc_commitment;
  pub_signals.splice(PROVE_RSA_CURRENT_DATE_INDEX, 0, ...getDateNum(current_date));
  pub_signals[PROVE_RSA_USER_IDENTIFIER_INDEX] = user_identifier;
  pub_signals[PROVE_RSA_SCOPE_INDEX] = scope;

  let proof: Proof = {
    proof: {
      a: ['1', '1'],
      b: [
        ['1', '2'],
        ['3', '4'],
      ],
      c: ['5', '6'],
    },
    pub_signals: pub_signals,
  };
  return proof;
}

export function generateMockDSCVerifierInputs({
  blinded_dsc_commitment = '12',
}: {
  blinded_dsc_commitment?: string;
}): Proof {
  let pub_signals: string[] = [];

  pub_signals[DSC_BLINDED_DSC_COMMITMENT_INDEX] = blinded_dsc_commitment;

  let proof: Proof = {
    proof: {
      a: ['1', '1'],
      b: [
        ['1', '2'],
        ['3', '4'],
      ],
      c: ['5', '6'],
    },
    pub_signals: pub_signals,
  };
  return proof;
}

function getDateNum(date: Date = new Date()): string[] {
  const year = date.getUTCFullYear() % 100;
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();

  const dateNum = [
    Math.floor(year / 10),
    year % 10,
    Math.floor(month / 10),
    month % 10,
    Math.floor(day / 10),
    day % 10,
  ];

  return dateNum.map((num) => num.toString());
}

export function convertProofTypeIntoInput(proof: Proof) {
  return {
    a: proof.proof.a,
    b: proof.proof.b,
    c: proof.proof.c,
    pubSignals: proof.pub_signals,
  };
}
