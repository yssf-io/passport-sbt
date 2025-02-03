// import { ethers } from 'ethers';
import { getCurrentDateYYMMDD } from '../../../common/src/utils/date';
import {
  attributeToPosition,
  circuitNameFromMode,
  REGISTER_CONTRACT_ADDRESS,
} from '../../../common/src/constants/constants';
import { derToBytes } from '../../../common/src/utils/bytes';
import forge from 'node-forge';
import { SKI_PEM, SKI_PEM_DEV } from './skiPem';
import {
  vkey_prove_rsa_65537_sha1,
  vkey_prove_rsa_65537_sha256,
  vkey_prove_rsapss_65537_sha256,
  vkey_dsc_rsa_65537_sha1,
  vkey_dsc_rsa_65537_sha256,
  vkey_dsc_rsapss_65537_sha256,
  vkey_vc_and_disclose,
} from '../../../common/src/constants/vkey';
import { Mode } from 'fs';
import { getCircuitNameOld } from '../../../common/src/utils/certificate_parsing/parseCertificateSimple';

export function getCurrentDateFormatted() {
  return getCurrentDateYYMMDD().map((datePart) => BigInt(datePart).toString());
}

export function getVkeyFromArtifacts(
  circuitMode: Mode,
  signatureAlgorithm: string,
  hashFunction: string
) {
  const circuit = circuitNameFromMode[circuitMode];
  let circuitName = '';
  if (circuit === 'vc_and_disclose') {
    circuitName = circuit;
  } else {
    circuitName = getCircuitNameOld(circuit, signatureAlgorithm, hashFunction);
  }
  // console.log('\x1b[90m%s\x1b[0m', 'circuit name:', circuitName);
  switch (circuitName) {
    case 'vc_and_disclose':
      return vkey_vc_and_disclose;
    case 'prove_rsa_65537_sha256':
      return vkey_prove_rsa_65537_sha256;
    case 'prove_rsa_65537_sha1':
      return vkey_prove_rsa_65537_sha1;
    case 'prove_rsapss_65537_sha256':
      return vkey_prove_rsapss_65537_sha256;
    case 'dsc_rsa_65537_sha1':
      return vkey_dsc_rsa_65537_sha1;
    case 'dsc_rsa_65537_sha256':
      return vkey_dsc_rsa_65537_sha256;
    case 'dsc_rsapss_65537_sha256':
      return vkey_dsc_rsapss_65537_sha256;
    default:
      throw new Error(`Invalid circuit name: ${circuitName}`);
  }
}

// // OpenPassport2Step
// export async function checkMerkleRoot(rpcUrl: string, merkleRoot: number) {
//   const provider = new ethers.JsonRpcProvider(rpcUrl);
//   const contract = new ethers.Contract(REGISTER_CONTRACT_ADDRESS, REGISTER_ABI, provider);
//   return await contract.checkRoot(merkleRoot);
// }

// OpenPassport1Step
function getCSCAPem(formattedValueAdjusted: string, dev_mode: boolean): string {
  const skiPem = dev_mode ? { ...SKI_PEM, ...SKI_PEM_DEV } : SKI_PEM;
  const pem = skiPem[formattedValueAdjusted];
  return pem;
}

export function verifyDSCValidity(dscCertificate: forge.pki.Certificate, dev_mode: boolean) {
  const authorityKeyIdentifierExt = dscCertificate.extensions.find(
    (ext) => ext.name === 'authorityKeyIdentifier'
  );
  const value = authorityKeyIdentifierExt.value;
  const byteArray = derToBytes(value);
  const formattedValue = byteArray.map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const formattedValueAdjusted = formattedValue.substring(8); // Remove the first '3016' from the formatted string
  const csca_pem = getCSCAPem(formattedValueAdjusted, dev_mode);
  if (csca_pem === null || csca_pem === undefined) {
    console.error('Error: CSCA PEM not found');
    throw new Error('CSCA PEM not found');
  }
  const csca_certificate = forge.pki.certificateFromPem(csca_pem);
  try {
    const caStore = forge.pki.createCaStore([csca_certificate]);
    const verified = forge.pki.verifyCertificateChain(caStore, [dscCertificate]);
    if (!verified) {
      throw new Error('DSC certificate verification failed');
    }
    const currentDate = new Date();
    if (
      currentDate < dscCertificate.validity.notBefore ||
      currentDate > dscCertificate.validity.notAfter
    ) {
      throw new Error('DSC certificate is not within its validity period');
    }
    return true;
  } catch (error) {
    console.error('DSC certificate validation error:', error);
    return false;
  }
}

export const areArraysEqual = (arr1: string[], arr2: string[]) =>
  arr1.length === arr2.length && arr1.every((value, index) => value === arr2[index]);
