import { ECDSA_K_LENGTH_FACTOR, k_dsc, k_dsc_ecdsa } from '../constants/constants';
import { Mode } from 'fs';
import { bigIntToHex, castToScope, castToUUID, UserIdType } from './circuits/uuid';
import { formatForbiddenCountriesListFromCircuitOutput, getAttributeFromUnpackedReveal } from './circuits/formatOutputs';
import { unpackReveal } from './circuits/formatOutputs';

export interface OpenPassportAttestation {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    userId: string;
    application: string;
    scope?: string;
    merkle_root?: string;
    attestation_id?: string;
    current_date?: string;
    issuing_state?: string;
    name?: string;
    passport_number?: string;
    nationality?: string;
    date_of_birth?: string;
    gender?: string;
    expiry_date?: string;
    older_than?: string;
    owner_of?: string;
    pubKey?: string[];
    valid?: boolean;
    nullifier?: string;
    blinded_dsc_commitment?: string;
  };
  proof: {
    mode: Mode;
    signatureAlgorithm: string;
    hashFunction: string;
    type: string;
    verificationMethod: string;
    value: {
      proof: string[];
      publicSignals: string[];
    };
    vkey: string;
  };
  dscProof: {
    signatureAlgorithm: string;
    hashFunction: string;
    type: string;
    verificationMethod: string;
    value: {
      proof: string[];
      publicSignals: string[];
    };
    vkey: string;
  };
  dsc: {
    type: string;
    value: string;
    encoding: string;
  };
}

export function buildAttestation(options: {
  userIdType: UserIdType;
  mode: Mode;
  proof: string[];
  publicSignals: string[];
  signatureAlgorithm: string;
  hashFunction: string;
  dscProof?: string[];
  dscPublicSignals?: string[];
  signatureAlgorithmDsc?: string;
  hashFunctionDsc?: string;
  dsc?: string;
}): OpenPassportDynamicAttestation {
  const {
    mode,
    proof,
    publicSignals,
    signatureAlgorithm,
    hashFunction,
    dscProof = [],
    dscPublicSignals = [],
    signatureAlgorithmDsc = '',
    hashFunctionDsc = '',
    dsc = '',
    userIdType,
  } = options;

  let kScaled: number;
  switch (signatureAlgorithm) {
    case 'ecdsa':
      kScaled = ECDSA_K_LENGTH_FACTOR * k_dsc_ecdsa;
      break;
    default:
      kScaled = k_dsc;
  }

  let parsedPublicSignals;
  switch (mode) {
    case 'vc_and_disclose':
      parsedPublicSignals = parsePublicSignalsDisclose(publicSignals);
      break;
    default:
      parsedPublicSignals = parsePublicSignalsProve(publicSignals, kScaled);
  }

  const rawUserId = parsedPublicSignals.user_identifier;
  let userId: string;
  switch (userIdType) {
    case 'ascii':
      userId = castToScope(BigInt(rawUserId));
      break;
    case 'hex':
      userId = bigIntToHex(BigInt(rawUserId));
      break;
    case 'uuid':
      userId = castToUUID(BigInt(rawUserId));
      break;
    default:
      userId = rawUserId;
  }

  const scope = castToScope(BigInt(parsedPublicSignals.scope));

  // Unpack the revealed data
  const unpackedReveal = unpackReveal(parsedPublicSignals.revealedData_packed);

  const attributeNames = [
    'issuing_state',
    'name',
    'passport_number',
    'nationality',
    'date_of_birth',
    'gender',
    'expiry_date',
    'older_than',
  ];
  const formattedCountryList = formatForbiddenCountriesListFromCircuitOutput(
    parsedPublicSignals.forbidden_countries_list_packed_disclosed
  );
  const credentialSubject: any = {
    userId: userId,
    application: scope,
    nullifier: bigIntToHex(BigInt(parsedPublicSignals.nullifier)),
    scope: scope,
    current_date: parsedPublicSignals.current_date.toString(),
    blinded_dsc_commitment: parsedPublicSignals.blinded_dsc_commitment ?? '',
    not_in_ofac_list: parsedPublicSignals.ofac_result.toString(),
    not_in_countries: formattedCountryList,
  };

  attributeNames.forEach((attrName) => {
    const value = getAttributeFromUnpackedReveal(unpackedReveal, attrName);
    if (value !== undefined && value !== null) {
      credentialSubject[attrName] = value;
    }
  });
  // Include pubKey if needed
  credentialSubject.pubKey = parsedPublicSignals.pubKey_disclosed ?? [];

  const attestation: OpenPassportAttestation = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://openpassport.app'],
    type: ['OpenPassportAttestation', 'PassportCredential'],
    issuer: 'https://openpassport.app',
    issuanceDate: new Date().toISOString(),
    credentialSubject: credentialSubject,
    proof: {
      mode: mode,
      signatureAlgorithm: signatureAlgorithm,
      hashFunction: hashFunction,
      type: 'ZeroKnowledgeProof',
      verificationMethod: 'https://github.com/zk-passport/openpassport',
      value: {
        proof: proof,
        publicSignals: publicSignals,
      },
      vkey: 'https://github.com/zk-passport/openpassport/blob/main/common/src/constants/vkey.ts',
    },
    dscProof: {
      signatureAlgorithm: signatureAlgorithmDsc,
      hashFunction: hashFunctionDsc,
      type: 'ZeroKnowledgeProof',
      verificationMethod: 'https://github.com/zk-passport/openpassport',
      value: {
        proof: dscProof || [],
        publicSignals: dscPublicSignals || [],
      },
      vkey: 'https://github.com/zk-passport/openpassport/blob/main/common/src/constants/vkey.ts',
    },
    dsc: {
      type: 'X509Certificate',
      value: dsc || '',
      encoding: 'PEM',
    },
  };

  // Return an instance of OpenPassportDynamicAttestation
  return new OpenPassportDynamicAttestation(attestation, userIdType);
}
// New OpenPassportDynamicAttestation class extending OpenPassportAttestation
export class OpenPassportDynamicAttestation implements OpenPassportAttestation {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    userId: string;
    application: string;
    scope?: string;
    merkle_root?: string;
    attestation_id?: string;
    current_date?: string;
    issuing_state?: string;
    name?: string;
    passport_number?: string;
    nationality?: string;
    date_of_birth?: string;
    gender?: string;
    expiry_date?: string;
    older_than?: string;
    owner_of?: string;
    pubKey?: string[];
    valid?: boolean;
    nullifier?: string;
  };
  proof: {
    mode: Mode;
    signatureAlgorithm: string;
    hashFunction: string;
    type: string;
    verificationMethod: string;
    value: {
      proof: string[];
      publicSignals: string[];
    };
    vkey;
  };
  dscProof: {
    signatureAlgorithm: string;
    hashFunction: string;
    type: string;
    verificationMethod: string;
    value: {
      proof: string[];
      publicSignals: string[];
    };
    vkey;
  };
  dsc: {
    type: string;
    value: string;
    encoding: string;
  };

  private parsedPublicSignals: any;
  private userIdType: UserIdType;

  constructor(attestation: OpenPassportAttestation, userIdType: UserIdType = 'uuid') {
    this['@context'] = attestation['@context'];
    this.type = attestation.type;
    this.issuer = attestation.issuer;
    this.issuanceDate = attestation.issuanceDate;
    this.credentialSubject = attestation.credentialSubject;
    this.proof = attestation.proof;
    this.dscProof = attestation.dscProof;
    this.dsc = attestation.dsc;
    this.userIdType = userIdType;
  }

  private parsePublicSignals() {
    if (this.proof.mode === 'vc_and_disclose') {
      return parsePublicSignalsDisclose(this.proof.value.publicSignals);
    } else {
      let kScaled: number;
      switch (this.proof.signatureAlgorithm) {
        case 'ecdsa':
          kScaled = ECDSA_K_LENGTH_FACTOR * k_dsc_ecdsa;
          break;
        default:
          kScaled = k_dsc;
      }
      return parsePublicSignalsProve(this.proof.value.publicSignals, kScaled);
    }

    // Parse the public signals
  }

  getUserId(): string {
    const parsedPublicSignals = this.parsePublicSignals();
    const rawUserId = (parsedPublicSignals as any).user_identifier;
    switch (this.userIdType) {
      case 'ascii':
        return castToScope(BigInt(rawUserId));
      case 'hex':
        return bigIntToHex(BigInt(rawUserId));
      case 'uuid':
        return castToUUID(BigInt(rawUserId));
      default:
        return rawUserId;
    }
  }

  getNullifier(): string {
    const parsedPublicSignals = this.parsePublicSignals();
    return bigIntToHex(BigInt(parsedPublicSignals.nullifier));
  }

  getCommitment(): string {
    const parsedPublicSignals = this.parsePublicSignals();
    if (this.proof.mode === 'vc_and_disclose') {
      return '';
    } else {
      return (parsedPublicSignals as any).commitment;
    }
  }

  getNationality(): string {
    const parsedPublicSignals = this.parsePublicSignals();
    const revealedData_packed = (parsedPublicSignals as any).revealedData_packed;
    const unpackedReveal = unpackReveal(revealedData_packed);
    return getAttributeFromUnpackedReveal(unpackedReveal, 'nationality');
  }

  getCSCAMerkleRoot(): string {
    if (this.dscProof.value.publicSignals) {
      const parsedPublicSignalsDsc = parsePublicSignalsDsc(this.dscProof.value.publicSignals);
      return parsedPublicSignalsDsc.merkle_root;
    } else {
      throw new Error('No DSC proof found');
    }
  }
}

export function parsePublicSignalsProve(publicSignals, kScaled) {
  return {
    nullifier: publicSignals[0],
    revealedData_packed: [publicSignals[1], publicSignals[2], publicSignals[3]],
    older_than: [publicSignals[4], publicSignals[5]],
    pubKey_disclosed: publicSignals.slice(6, 6 + kScaled),
    forbidden_countries_list_packed_disclosed: publicSignals.slice(6 + kScaled, 8 + kScaled),
    ofac_result: publicSignals[8 + kScaled],
    commitment: publicSignals[9 + kScaled],
    blinded_dsc_commitment: publicSignals[10 + kScaled],
    current_date: publicSignals.slice(11 + kScaled, 11 + kScaled + 6),
    user_identifier: publicSignals[17 + kScaled],
    scope: publicSignals[18 + kScaled],
  };
}

export function parsePublicSignalsDsc(publicSignals) {
  return {
    blinded_dsc_commitment: publicSignals[0],
    merkle_root: publicSignals[1],
  };
}

export function parsePublicSignalsDisclose(publicSignals) {
  return {
    nullifier: publicSignals[0],
    revealedData_packed: publicSignals.slice(1, 4),
    older_than: publicSignals.slice(4, 6),
    forbidden_countries_list_packed_disclosed: publicSignals.slice(6, 8),
    ofac_result: publicSignals[8],
    attestation_id: publicSignals[9],
    merkle_root: publicSignals[10],
    scope: publicSignals[11],
    current_date: publicSignals.slice(12, 18),
    user_identifier: publicSignals[18],
    smt_root: publicSignals[19],
  };
}
