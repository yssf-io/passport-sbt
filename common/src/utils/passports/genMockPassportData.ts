import { PassportData } from '../types';
import * as forge from 'node-forge';
import * as asn1 from 'asn1js';
import elliptic from 'elliptic';
import { getHashLen, hash } from '../hash';
import {
  mock_dsc_key_sha1_rsa_4096,
  mock_dsc_key_sha256_ecdsa,
  mock_dsc_key_sha256_rsa_4096,
  mock_dsc_key_sha256_rsapss_2048,
  mock_dsc_key_sha256_rsapss_4096,
  mock_dsc_sha1_rsa_4096,
  mock_dsc_sha256_ecdsa,
  mock_dsc_sha256_rsa_4096,
  mock_dsc_sha256_rsapss_2048,
  mock_dsc_sha256_rsapss_4096,
  mock_dsc_key_sha1_ecdsa,
  mock_dsc_sha1_ecdsa,
  mock_dsc_key_sha384_ecdsa,
  mock_dsc_sha384_ecdsa,
  mock_dsc_key_sha256_brainpoolP256r1,
  mock_dsc_sha256_brainpoolP256r1,
  mock_dsc_key_sha256_rsa_3_2048,
  mock_dsc_sha256_rsa_3_2048,
  mock_dsc_key_sha256_rsa_65537_3072,
  mock_dsc_sha256_rsa_65537_3072,
  mock_dsc_key_sha256_rsapss_3_4096,
  mock_dsc_sha256_rsapss_3_4096,
  mock_dsc_key_sha256_rsapss_3_3072,
  mock_dsc_sha256_rsapss_3_3072,
  mock_dsc_key_sha384_rsapss_65537_3072,
  mock_dsc_sha384_rsapss_65537_3072,
  mock_dsc_key_sha256_rsapss_65537_3072,
  mock_dsc_sha256_rsapss_65537_3072,
  mock_dsc_key_rsapss_65537_4096,
  mock_dsc_sha256_rsapss_65537_4096,
  mock_dsc_key_sha384_brainpoolP384r1,
  mock_dsc_sha384_brainpoolP384r1,
  mock_dsc_key_sha256_secp384r1,
  mock_dsc_sha256_secp384r1,
  mock_dsc_key_sha384_brainpoolP256r1,
  mock_dsc_sha384_brainpoolP256r1,
  mock_dsc_key_sha512_brainpoolP256r1,
  mock_dsc_sha512_brainpoolP256r1,
  mock_dsc_key_sha512_brainpoolP384r1,
  mock_dsc_sha512_brainpoolP384r1,
  mock_dsc_key_sha1_brainpoolP224r1,
  mock_dsc_sha1_brainpoolP224r1,
  mock_dsc_key_sha256_brainpoolP224r1,
  mock_dsc_sha256_brainpoolP224r1,
  mock_dsc_key_sha512_brainpoolP512r1,
  mock_dsc_sha512_brainpoolP512r1,
  mock_dsc_key_sha224_braipoolP224r1,
  mock_dsc_sha224_brainpoolP224r1,
  mock_dsc_key_sha512_rsa_65537_4096,
  mock_dsc_sha512_rsa_65537_4096,
  mock_dsc_key_sha256_rsa_3_4096,
  mock_dsc_sha256_rsa_3_4096,
  mock_dsc_key_sha512_rsa_65537_2048,
  mock_dsc_sha512_rsa_65537_2048,
} from '../../constants/mockCertificates';
import { countryCodes } from '../../constants/constants';
import { parseCertificateSimple } from '../certificate_parsing/parseCertificateSimple';
import { SignatureAlgorithm } from '../types';
import { PublicKeyDetailsECDSA, PublicKeyDetailsRSAPSS } from '../certificate_parsing/dataStructure';
import { getCurveForElliptic } from '../certificate_parsing/curves';
import { formatAndConcatenateDataHashes, formatMrz } from './format';
import { generateSignedAttr } from './format';

function generateRandomBytes(length: number): number[] {
  // Generate numbers between -128 and 127 to match the existing signed byte format
  return Array.from({ length }, () => Math.floor(Math.random() * 256) - 128);
}

function generateDataGroupHashes(mrzHash: number[], hashLen: number): [number, number[]][] {
  // Generate hashes for DGs 2-15 (excluding some DGs that aren't typically used)
  const dataGroups: [number, number[]][] = [
    [1, mrzHash], // DG1 must be the MRZ hash
    [2, generateRandomBytes(hashLen)],
    [3, generateRandomBytes(hashLen)],
    [4, generateRandomBytes(hashLen)],
    [5, generateRandomBytes(hashLen)],
    [7, generateRandomBytes(hashLen)],
    [11, generateRandomBytes(hashLen)],
    [12, generateRandomBytes(hashLen)],
    [14, generateRandomBytes(hashLen)],
  ];

  return dataGroups;
}

export function genMockPassportData(
  dgHashAlgo: string,
  eContentHashAlgo: string,
  signatureType: SignatureAlgorithm,
  nationality: keyof typeof countryCodes,
  birthDate: string,
  expiryDate: string,
  passportNumber: string = '15AA81234',
  lastName: string = 'DUPONT',
  firstName: string = 'ALPHONSE HUGHUES ALBERT'
): PassportData {
  if (birthDate.length !== 6 || expiryDate.length !== 6) {
    throw new Error('birthdate and expiry date have to be in the "YYMMDD" format');
  }

  // Prepare last name: Convert to uppercase, remove invalid characters, split by spaces, and join with '<'
  const lastNameParts = lastName
    .toUpperCase()
    .replace(/[^A-Z< ]/g, '')
    .split(' ');
  const formattedLastName = lastNameParts.join('<');

  // Prepare first name: Convert to uppercase, remove invalid characters, split by spaces, and join with '<'
  const firstNameParts = firstName
    .toUpperCase()
    .replace(/[^A-Z< ]/g, '')
    .split(' ');
  const formattedFirstName = firstNameParts.join('<');

  // Build the first line of MRZ
  let mrzLine1 = `P<${nationality}${formattedLastName}<<${formattedFirstName}`;

  // Pad the first line with '<' to make it exactly 44 characters
  mrzLine1 = mrzLine1.padEnd(44, '<');

  if (mrzLine1.length > 44) {
    throw new Error('First line of MRZ exceeds 44 characters');
  }

  // Build the second line of MRZ
  const mrzLine2 = `${passportNumber}4${nationality}${birthDate}1M${expiryDate}5<<<<<<<<<<<<<<02`;

  // Combine both lines to form the MRZ
  const mrz = mrzLine1 + mrzLine2;

  // Validate the MRZ length
  if (mrz.length !== 88) {
    throw new Error(`MRZ must be 88 characters long, got ${mrz.length}`);
  }

  let privateKeyPem: string;
  let dsc: string;

  switch (signatureType) {
    case 'rsa_sha1_65537_2048':
      privateKeyPem = mock_dsc_key_sha1_rsa_4096;
      dsc = mock_dsc_sha1_rsa_4096;
      break;
    case 'rsa_sha1_65537_4096':
      privateKeyPem = mock_dsc_key_sha1_rsa_4096;
      dsc = mock_dsc_sha1_rsa_4096;
      break;
    case 'rsa_sha256_65537_2048':
      privateKeyPem = mock_dsc_key_sha256_rsa_4096;
      dsc = mock_dsc_sha256_rsa_4096;
      break;
    case 'rsapss_sha256_65537_2048':
      privateKeyPem = mock_dsc_key_sha256_rsapss_4096;
      dsc = mock_dsc_sha256_rsapss_4096;
      break;
    case 'rsapss_sha256_3_4096':
      privateKeyPem = mock_dsc_key_sha256_rsapss_3_4096;
      dsc = mock_dsc_sha256_rsapss_3_4096;
      break;
    case 'rsapss_sha256_3_3072':
      privateKeyPem = mock_dsc_key_sha256_rsapss_3_3072;
      dsc = mock_dsc_sha256_rsapss_3_3072;
      break;
    case 'rsapss_sha384_65537_3072':
      privateKeyPem = mock_dsc_key_sha384_rsapss_65537_3072;
      dsc = mock_dsc_sha384_rsapss_65537_3072;
      break;
    case 'ecdsa_sha256_secp256r1_256':
      privateKeyPem = mock_dsc_key_sha256_ecdsa;
      dsc = mock_dsc_sha256_ecdsa;
      break;
    case 'ecdsa_sha1_secp256r1_256':
      privateKeyPem = mock_dsc_key_sha1_ecdsa;
      dsc = mock_dsc_sha1_ecdsa;
      break;
    case 'ecdsa_sha384_secp384r1_384':
      privateKeyPem = mock_dsc_key_sha384_ecdsa;
      dsc = mock_dsc_sha384_ecdsa;
      break;
    case 'ecdsa_sha256_secp384r1_384':
      privateKeyPem = mock_dsc_key_sha256_secp384r1;
      dsc = mock_dsc_sha256_secp384r1;
      break;
    case 'ecdsa_sha256_brainpoolP256r1_256':
      privateKeyPem = mock_dsc_key_sha256_brainpoolP256r1;
      dsc = mock_dsc_sha256_brainpoolP256r1;
      break;
    case 'ecdsa_sha384_brainpoolP256r1_256':
      privateKeyPem = mock_dsc_key_sha384_brainpoolP256r1;
      dsc = mock_dsc_sha384_brainpoolP256r1;
      break;
    case 'ecdsa_sha512_brainpoolP256r1_256':
      privateKeyPem = mock_dsc_key_sha512_brainpoolP256r1;
      dsc = mock_dsc_sha512_brainpoolP256r1;
      break;
    case 'rsa_sha256_3_2048':
      privateKeyPem = mock_dsc_key_sha256_rsa_3_2048;
      dsc = mock_dsc_sha256_rsa_3_2048;
      break;
    case 'rsa_sha256_65537_3072':
      privateKeyPem = mock_dsc_key_sha256_rsa_65537_3072;
      dsc = mock_dsc_sha256_rsa_65537_3072;
      break;
    case 'rsapss_sha256_65537_3072':
      privateKeyPem = mock_dsc_key_sha256_rsapss_65537_3072;
      dsc = mock_dsc_sha256_rsapss_65537_3072;
      break;
    case 'rsapss_sha256_65537_4096':
      privateKeyPem = mock_dsc_key_rsapss_65537_4096;
      dsc = mock_dsc_sha256_rsapss_65537_4096;
      break;
    case 'ecdsa_sha384_brainpoolP384r1_384':
      privateKeyPem = mock_dsc_key_sha384_brainpoolP384r1;
      dsc = mock_dsc_sha384_brainpoolP384r1;
      break;
    case 'ecdsa_sha512_brainpoolP384r1_384':
      privateKeyPem = mock_dsc_key_sha512_brainpoolP384r1;
      dsc = mock_dsc_sha512_brainpoolP384r1;
      break;
    case 'ecdsa_sha1_brainpoolP224r1_224':
      privateKeyPem = mock_dsc_key_sha1_brainpoolP224r1;
      dsc = mock_dsc_sha1_brainpoolP224r1;
      break;
    case 'ecdsa_sha224_brainpoolP224r1_224':
      privateKeyPem = mock_dsc_key_sha224_braipoolP224r1;
      dsc = mock_dsc_sha224_brainpoolP224r1;
      break;
    case 'ecdsa_sha256_brainpoolP224r1_224':
      privateKeyPem = mock_dsc_key_sha256_brainpoolP224r1;
      dsc = mock_dsc_sha256_brainpoolP224r1;
      break;
    case 'ecdsa_sha512_brainpoolP512r1_512':
      privateKeyPem = mock_dsc_key_sha512_brainpoolP512r1;
      dsc = mock_dsc_sha512_brainpoolP512r1;
      break;
    case 'rsa_sha256_65537_4096':
      privateKeyPem = mock_dsc_key_sha256_rsa_4096;
      dsc = mock_dsc_sha256_rsa_4096;
      break;
    case 'rsa_sha512_65537_4096':
      privateKeyPem = mock_dsc_key_sha512_rsa_65537_4096;
      dsc = mock_dsc_sha512_rsa_65537_4096;
      break;
    case 'rsa_sha512_65537_2048':
      privateKeyPem = mock_dsc_key_sha512_rsa_65537_2048;
      dsc = mock_dsc_sha512_rsa_65537_2048;
      break;
    case 'rsa_sha256_3_4096':
      privateKeyPem = mock_dsc_key_sha256_rsa_3_4096;
      dsc = mock_dsc_sha256_rsa_3_4096;
      break;
  }

  // Generate MRZ hash first
  const mrzHash = hash(dgHashAlgo, formatMrz(mrz));

  // Generate random hashes for other DGs, passing mrzHash for DG1
  const dataGroupHashes = generateDataGroupHashes(mrzHash as number[], getHashLen(dgHashAlgo));

  const eContent = formatAndConcatenateDataHashes(dataGroupHashes, 63);

  const signedAttr = generateSignedAttr(hash(eContentHashAlgo, eContent) as number[]);
  const hashAlgo = signatureType.split('_')[1];
  const signature = sign(privateKeyPem, dsc, hashAlgo, signedAttr);
  const signatureBytes = Array.from(signature, (byte) => (byte < 128 ? byte : byte - 256));

  return {
    dsc: dsc,
    mrz: mrz,
    dg2Hash: dataGroupHashes.find(([dgNum]) => dgNum === 2)?.[1] || [],
    eContent: eContent,
    signedAttr: signedAttr,
    encryptedDigest: signatureBytes,
    photoBase64: 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABjElEQVR42mL8//8/AyUYiBQYmIy3...',
    mockUser: true,
    parsed: false,
  };
}

function sign(
  privateKeyPem: string,
  dsc: string,
  hashAlgorithm: string,
  eContent: number[]
): number[] {
  const { signatureAlgorithm, publicKeyDetails } = parseCertificateSimple(dsc);

  if (signatureAlgorithm === 'rsapss') {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const md = forge.md.sha256.create();
    md.update(forge.util.binary.raw.encode(new Uint8Array(eContent)));
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: parseInt((publicKeyDetails as PublicKeyDetailsRSAPSS).saltLength),
    });
    const signatureBytes = privateKey.sign(md, pss);
    return Array.from(signatureBytes, (c: string) => c.charCodeAt(0));
  } else if (signatureAlgorithm === 'ecdsa') {
    const curve = (publicKeyDetails as PublicKeyDetailsECDSA).curve;
    let curveForElliptic = getCurveForElliptic(curve);
    const ec = new elliptic.ec(curveForElliptic);

    const privateKeyDer = Buffer.from(
      privateKeyPem.replace(/-----BEGIN EC PRIVATE KEY-----|\n|-----END EC PRIVATE KEY-----/g, ''),
      'base64'
    );
    const asn1Data = asn1.fromBER(privateKeyDer);
    const privateKeyBuffer = (asn1Data.result.valueBlock as any).value[1].valueBlock.valueHexView;

    const keyPair = ec.keyFromPrivate(privateKeyBuffer);
    const msgHash = hash(hashAlgorithm, eContent, 'hex');

    const signature = keyPair.sign(msgHash, 'hex');
    const signatureBytes = Array.from(Buffer.from(signature.toDER(), 'hex'));

    return signatureBytes;
  } else {
    const privKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const md = forge.md[hashAlgorithm].create();
    md.update(forge.util.binary.raw.encode(new Uint8Array(eContent)));
    const forgeSignature = privKey.sign(md);
    return Array.from(forgeSignature, (c: string) => c.charCodeAt(0));
  }
}