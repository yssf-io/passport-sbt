import {
  PUBKEY_TREE_DEPTH,
  MAX_PADDED_ECONTENT_LEN,
  MAX_PADDED_SIGNED_ATTR_LEN,
  SignatureAlgorithmIndex,
  max_dsc_bytes,
  max_csca_bytes,
} from '../../constants/constants';
import { PassportData } from '../types';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { getCountryLeaf, getNameLeaf, getNameDobLeaf, getPassportNumberLeaf } from '../trees';
import { SMT } from '@openpassport/zk-kit-smt';
import {
  extractSignatureFromDSC,
  findStartPubKeyIndex,
  formatCertificatePubKeyDSC,
  formatSignatureDSCCircuit,
  generateCommitment,
  getCertificatePubKey,
  getPassportSignatureInfos,
  getSignatureAlgorithmFullName,
  pad,
  padWithZeroes,
} from '../passports/passport';
import { toUnsignedByte } from '../bytes';
import { customHasher, hash, packBytesAndPoseidon } from '../hash';
import { formatMrz } from '../passports/format';
import { castFromUUID, stringToAsciiBigIntArray } from './uuid';
import { getCurrentDateYYMMDD } from '../date';
import { castFromScope } from './uuid';
import { formatCountriesList } from './formatInputs';
import { generateMerkleProof, generateSMTProof } from '../trees';
import { getCertificateFromPem, getTBSBytes, parseCertificateSimple } from '../certificate_parsing/parseCertificateSimple';
import { findStartIndex, findStartIndexEC, getCSCAFromSKI, getCSCAModulusProof } from '../csca';
import { PublicKeyDetailsECDSA, PublicKeyDetailsRSA } from '../certificate_parsing/dataStructure';
import { parseDscCertificateData } from '../passports/passport_parsing/parseDscCertificateData';
import { getLeafCscaTree } from '../pubkeyTree';

export function generateCircuitInputsDSC(
  dscCertificate: string,
  devMode: boolean = false
) {
  const dscParsed = parseCertificateSimple(dscCertificate);
  const dscMetadata = parseDscCertificateData(dscParsed);
  const cscaParsed = parseCertificateSimple(dscMetadata.csca);
  const cscaTbsBytesPadded = padWithZeroes(Array.from(cscaParsed.tbsBytes), max_csca_bytes); // TODO: change this to the actual hash algorithm
  console.log('js: cscaTbsBytesPadded', cscaTbsBytesPadded);
  console.log('js: cscaTbsBytesPadded length', cscaTbsBytesPadded.length);

  const dscTbsBytes = dscParsed.tbsBytes;
  console.log('js: dscTbsBytes', dscTbsBytes);
  console.log('js: dscTbsBytes length', dscTbsBytes.length);
  // const dscTbsBytesPadded = padWithZeroes(Array.from(dscTbsBytes), max_dsc_bytes);
  // console.log('js: dscTbsBytesPadded', dscTbsBytesPadded);
  // console.log('js: dscTbsBytesPadded length', dscTbsBytesPadded.length);

  const [dscTbsBytesPadded, dscTbsBytesLen] = pad(cscaParsed.hashAlgorithm)( // do we want to keep this padding for the commitment? Not sure
    dscTbsBytes,
    max_dsc_bytes
  );
  console.log('js: dscTbsBytesPadded', dscTbsBytesPadded);
  console.log('js: dscTbsBytesPadded length', dscTbsBytesPadded.length);

  // TODO: get the CSCA inclusion proof
  const leaf = getLeafCscaTree(cscaParsed);
  const [root, proof] = getCSCAModulusProof(leaf);

  // Parse CSCA certificate and get its public key
  const csca_pubKey_formatted = getCertificatePubKey(
    cscaParsed,
    cscaParsed.signatureAlgorithm,
    cscaParsed.hashAlgorithm
  );
  const modulus = (cscaParsed.publicKeyDetails as PublicKeyDetailsRSA).modulus;
  const modulus_bytes = Array.from(Buffer.from(modulus, 'hex'));
  console.log('js: modulus_bytes', modulus_bytes);
  console.log('js: modulus_bytes[modulus_bytes.length - 1]', modulus_bytes[modulus_bytes.length - 1]);
  console.log('js: modulus_bytes length', modulus_bytes.length);

  console.log('js: csca_pubKey_formatted', csca_pubKey_formatted);
  console.log('js: csca_pubKey_formatted length', csca_pubKey_formatted.length);

  const csca_pubkey_length_bytes = Number(cscaParsed.publicKeyDetails.bits) / 8;
  console.log('js: csca_pubkey_length_bytes', csca_pubkey_length_bytes);

  const signatureRaw = extractSignatureFromDSC(dscCertificate);
  // console.log('js: signatureRaw', signatureRaw);
  const signature = formatSignatureDSCCircuit(dscMetadata.cscaSignatureAlgorithm, dscMetadata.cscaHashAlgorithm, cscaParsed, signatureRaw,);
  // console.log('js: signature', signature);

  // Get start index of CSCA pubkey based on algorithm
  const startIndex = findStartPubKeyIndex(cscaParsed, cscaTbsBytesPadded, cscaParsed.signatureAlgorithm);
  console.log('js: startIndex', startIndex);

  return {
    raw_csca: cscaTbsBytesPadded.map(x => x.toString()),
    raw_csca_actual_length: [BigInt(cscaParsed.tbsBytes.length).toString()],
    csca_pubKey_offset: [startIndex.toString()],
    raw_dsc: Array.from(dscTbsBytesPadded).map(x => x.toString()),
    raw_dsc_actual_length: [BigInt(dscTbsBytesLen).toString()],
    csca_pubKey: csca_pubKey_formatted,
    signature,
    // merkle_root: [BigInt(root).toString()],
    // path: proof.pathIndices.map(index => index.toString()),
    // siblings: proof.siblings.flat().map(sibling => sibling.toString()),
  };
}

export function generateCircuitInputsRegister(
  secret: number | string,
  dsc_secret: number | string,
  passportData: PassportData
) {
  if (!passportData.parsed) {
    throw new Error('Passport data is not parsed');
  }
  const { mrz, eContent, signedAttr } = passportData;
  const passportMetadata = passportData.passportMetadata;

  const { pubKey, signature, signatureAlgorithmFullName } = getPassportSignatureInfos(passportData);
  const mrz_formatted = formatMrz(mrz);

  if (eContent.length > MAX_PADDED_ECONTENT_LEN[signatureAlgorithmFullName]) {
    console.error(
      `eContent too long (${eContent.length} bytes). Max length is ${MAX_PADDED_ECONTENT_LEN[signatureAlgorithmFullName]} bytes.`
    );
    throw new Error(
      `This length of datagroups (${eContent.length} bytes) is currently unsupported. Please contact us so we add support!`
    );
  }

  const [eContentPadded, eContentLen] = pad(passportMetadata.eContentHashFunction)(
    new Uint8Array(eContent),
    MAX_PADDED_ECONTENT_LEN[passportMetadata.dg1HashFunction]
  );
  const [signedAttrPadded, signedAttrPaddedLen] = pad(passportMetadata.signedAttrHashFunction)(
    new Uint8Array(signedAttr),
    MAX_PADDED_SIGNED_ATTR_LEN[passportMetadata.eContentHashFunction]
  );


  // const dsc_pubkey_length_bytes = signatureAlgorithm === 'ecdsa'
  // ? (Number((publicKeyDetails as PublicKeyDetailsECDSA).bits) / 8) * 2
  // : Number((publicKeyDetails as PublicKeyDetailsRSA).bits) / 8;

  // const certificateData = parseCertificateSimple(dscCertificate);

  // const signatureAlgorithmFullName = getSignatureAlgorithmFullName(
  //   certificateData,
  //   signatureAlgorithm,
  //   hashAlgorithm
  // );

  // const pubKey_dsc = formatCertificatePubKeyDSC(
  //   certificateData,
  //   signatureAlgorithm,
  // );

  // console.log('js: pubKey_dsc', pubKey_dsc);

  // const { 
  //   signatureAlgorithm,
  //   hashAlgorithm,
  //   publicKeyDetails,
  //   authorityKeyIdentifier, 
  // } = certificateData;

  const pubKey_csca = getCertificatePubKey(
    passportData.csca_parsed,
    passportMetadata.cscaSignatureAlgorithm,
    passportMetadata.cscaHashFunction
  );
  const pubKey_csca_hash = customHasher(pubKey_csca);

  const inputs = {
    dg1: mrz_formatted,
    dg1_hash_offset: passportMetadata.dg1HashOffset,
    eContent: eContentPadded,
    eContent_padded_length: eContentLen,
    signed_attr: signedAttrPadded,
    signed_attr_padded_length: signedAttrPaddedLen,
    signed_attr_econtent_hash_offset: passportMetadata.eContentHashOffset,
    pubKey_dsc: pubKey,
    signature_passport: signature,
    pubKey_csca_hash: pubKey_csca_hash,
    secret: secret,
    salt: dsc_secret,
  };

  return Object.entries(inputs)
    .map(([key, value]) => ({
      [key]: formatInput(value),
    }))
    .reduce((acc, curr) => ({ ...acc, ...curr }), {});
}

export function generateCircuitInputsVCandDisclose(
  secret: string,
  attestation_id: string,
  passportData: PassportData,
  scope: string,
  selector_dg1: string[],
  selector_older_than: string | number,
  merkletree: LeanIMT,
  majority: string,
  name_smt: SMT,
  selector_ofac: string | number,
  forbidden_countries_list: string[],
  user_identifier: string
) {
  const formattedMrz = formatMrz(passportData.mrz);
  const passportMetadata = passportData.passportMetadata;
  const eContent_shaBytes = hash(
    passportMetadata.eContentHashFunction,
    Array.from(passportData.eContent),
    'bytes'
  );
  const eContent_packed_hash = packBytesAndPoseidon(
    (eContent_shaBytes as number[]).map((byte) => byte & 0xff)
  );

  const pubKey_dsc = getCertificatePubKey(
    passportData.dsc_parsed,
    passportMetadata.signatureAlgorithm,
    passportMetadata.signedAttrHashFunction
  );
  const pubKey_dsc_hash = customHasher(pubKey_dsc);

  const pubKey_csca = getCertificatePubKey(
    passportData.csca_parsed,
    passportMetadata.cscaSignatureAlgorithm,
    passportMetadata.cscaHashFunction
  );
  const pubKey_csca_hash = customHasher(pubKey_csca);

  const commitment = generateCommitment(secret, attestation_id, passportData);
  const index = findIndexInTree(merkletree, BigInt(commitment));
  const { merkleProofSiblings, merkleProofIndices, depthForThisOne } = generateMerkleProof(
    merkletree,
    index,
    PUBKEY_TREE_DEPTH
  );
  const formattedMajority = majority.length === 1 ? `0${majority}` : majority;
  const majority_ascii = formattedMajority.split('').map((char) => char.charCodeAt(0));

  // SMT -  OFAC
  const name_leaf = getNameLeaf(formattedMrz.slice(10, 49)); // [6-44] + 5 shift
  const {
    root: smt_root,
    closestleaf: smt_leaf_key,
    siblings: smt_siblings,
  } = generateSMTProof(name_smt, name_leaf);

  return {
    secret: formatInput(secret),
    attestation_id: formatInput(attestation_id),
    dg1: formatInput(formattedMrz),
    eContent_shaBytes_packed_hash: formatInput(eContent_packed_hash),
    pubKey_dsc_hash: formatInput(pubKey_dsc_hash),
    pubKey_csca_hash: formatInput(pubKey_csca_hash),
    merkle_root: formatInput(merkletree.root),
    merkletree_size: formatInput(depthForThisOne),
    path: formatInput(merkleProofIndices),
    siblings: formatInput(merkleProofSiblings),
    selector_dg1: formatInput(selector_dg1),
    selector_older_than: formatInput(selector_older_than),
    scope: formatInput(castFromScope(scope)),
    current_date: formatInput(getCurrentDateYYMMDD()),
    majority: formatInput(majority_ascii),
    user_identifier: formatInput(castFromUUID(user_identifier)),
    smt_root: formatInput(smt_root),
    smt_leaf_key: formatInput(smt_leaf_key),
    smt_siblings: formatInput(smt_siblings),
    selector_ofac: formatInput(selector_ofac),
    forbidden_countries_list: formatInput(formatCountriesList(forbidden_countries_list)),
  };
}

export function generateCircuitInputsOfac(
  passportData: PassportData,
  sparsemerkletree: SMT,
  proofLevel: number
) {
  const mrz_bytes = formatMrz(passportData.mrz);
  const passport_leaf = getPassportNumberLeaf(mrz_bytes.slice(49, 58));
  const namedob_leaf = getNameDobLeaf(mrz_bytes.slice(10, 49), mrz_bytes.slice(62, 68)); // [57-62] + 5 shift
  const name_leaf = getNameLeaf(mrz_bytes.slice(10, 49)); // [6-44] + 5 shift

  let root, closestleaf, siblings;
  if (proofLevel == 3) {
    ({ root, closestleaf, siblings } = generateSMTProof(sparsemerkletree, passport_leaf));
  } else if (proofLevel == 2) {
    ({ root, closestleaf, siblings } = generateSMTProof(sparsemerkletree, namedob_leaf));
  } else if (proofLevel == 1) {
    ({ root, closestleaf, siblings } = generateSMTProof(sparsemerkletree, name_leaf));
  } else {
    throw new Error('Invalid proof level');
  }

  return {
    dg1: formatInput(mrz_bytes),
    smt_leaf_key: formatInput(closestleaf),
    smt_root: formatInput(root),
    smt_siblings: formatInput(siblings),
  };
}

export function generateCircuitInputsCountryVerifier(
  passportData: PassportData,
  sparsemerkletree: SMT
) {
  const mrz_bytes = formatMrz(passportData.mrz);
  const usa_ascii = stringToAsciiBigIntArray('USA');
  const country_leaf = getCountryLeaf(usa_ascii, mrz_bytes.slice(7, 10));
  const { root, closestleaf, siblings } = generateSMTProof(sparsemerkletree, country_leaf);

  return {
    dg1: formatInput(mrz_bytes),
    hostCountry: formatInput(usa_ascii),
    smt_leaf_key: formatInput(closestleaf),
    smt_root: formatInput(root),
    smt_siblings: formatInput(siblings),
  };
}

// this get the commitment index whether it is a string or a bigint
// this is necessary rn because when the tree is send from the server in a serialized form,
// the bigints are converted to strings and I can't figure out how to use tree.import to load bigints there
export function findIndexInTree(tree: LeanIMT, commitment: bigint): number {
  let index = tree.indexOf(commitment);
  if (index === -1) {
    index = tree.indexOf(commitment.toString() as unknown as bigint);
  }
  if (index === -1) {
    throw new Error('This commitment was not found in the tree');
  } else {
    //  console.log(`Index of commitment in the registry: ${index}`);
  }
  return index;
}

export function formatInput(input: any) {
  if (Array.isArray(input)) {
    return input.map((item) => BigInt(item).toString());
  } else if (input instanceof Uint8Array) {
    return Array.from(input).map((num) => BigInt(num).toString());
  } else if (typeof input === 'string' && input.includes(',')) {
    const numbers = input
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '' && !isNaN(Number(s)))
      .map(Number);

    try {
      return numbers.map((num) => BigInt(num).toString());
    } catch (e) {
      throw e;
    }
  } else {
    return [BigInt(input).toString()];
  }
}