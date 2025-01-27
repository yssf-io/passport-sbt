import { sha384_512Pad, shaPad } from './shaPad';
import * as forge from 'node-forge';
import * as asn1 from 'asn1js';
import { CSCA_TREE_DEPTH, MODAL_SERVER_ADDRESS, SignatureAlgorithmIndex } from '../constants/constants';
import { poseidon2 } from 'poseidon-lite';
import { IMT } from '@openpassport/zk-kit-imt';
import serialized_csca_tree from '../../pubkeys/serialized_csca_tree.json';
import axios from 'axios';
import { getLeafCSCA } from './pubkeyTree';
import { SKI_PEM, SKI_PEM_DEV } from '../constants/skiPem';
import { formatInput } from './circuits/generateInputs';
// import { getCertificateFromPem, parseCertificate } from './certificates/handleCertificate';
import { parseCertificate } from '../utils/certificate_parsing/parseCertificate';
import { SignatureAlgorithm } from './types';
import { Certificate } from 'pkijs';
import { bytesToBigDecimal, hexToDecimal, splitToWords } from './bytes';
import { extractRSFromSignature, getNAndK } from './passports/passport';

export function findStartIndexEC(modulus: string, messagePadded: Uint8Array): number {
  const modulusNumArray = [];
  for (let i = 0; i < modulus.length; i += 2) {
    modulusNumArray.push(parseInt(modulus.slice(i, i + 2), 16));
  }

  let startIndex = -1;
  // For ECDSA, look for the ASN.1 tag for EC Point (0x04)
  const isECPoint = modulusNumArray[0] === 0x04;

  for (let i = 0; i < messagePadded.length - modulusNumArray.length + 1; i++) {
    let found = true;
    for (let j = 0; j < modulusNumArray.length; j++) {
      if (messagePadded[i + j] !== modulusNumArray[j]) {
        found = false;
        break;
      }
      if (found && (j === modulusNumArray.length - 1 || (isECPoint && j > 0))) {
        startIndex = i;
        break;
      }
    }
    if (startIndex !== -1) break;
  }

  if (startIndex === -1) {
    throw new Error('DSC Pubkey not found in CSCA certificate');
  }
  return startIndex;
}

export function findStartIndex(modulus: string, messagePadded: Uint8Array): number {
  const modulusNumArray = [];
  for (let i = 0; i < modulus.length; i += 2) {
    const hexPair = modulus.slice(i, i + 2);
    const number = parseInt(hexPair, 16);
    modulusNumArray.push(number);
  }

  const messagePaddedNumber = Array.from(messagePadded);

  // console.log('Modulus length:', modulusNumArray.length);
  // console.log('Message length:', messagePaddedNumber.length);
  // console.log('Modulus (hex):', modulusNumArray.map(n => n.toString(16).padStart(2, '0')).join(''));
  // console.log('Message (hex):', messagePaddedNumber.map(n => n.toString(16).padStart(2, '0')).join(''));

  for (let i = 0; i < messagePaddedNumber.length - modulusNumArray.length + 1; i++) {
    let matched = true;
    for (let j = 0; j < modulusNumArray.length; j++) {
      if (modulusNumArray[j] !== messagePaddedNumber[i + j]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return i;
    }
  }

  throw new Error('DSC Pubkey not found in certificate');
}

export function findOIDPosition(
  oid: string,
  message: Uint8Array
): { oid_index: number; oid_length: number } {
  // Convert OID string like "1.2.840.113549" to byte array
  const oidParts = oid.split('.').map(Number);

  // First byte is 40 * first number + second number
  const oidBytes = [40 * oidParts[0] + oidParts[1]];

  // Convert remaining parts to ASN.1 DER encoding
  for (let i = 2; i < oidParts.length; i++) {
    let value = oidParts[i];
    let bytes = [];

    // Handle multi-byte values
    if (value >= 128) {
      const tempBytes = [];
      while (value > 0) {
        tempBytes.unshift(value & 0x7f);
        value = value >>> 7;
      }
      // Set MSB for all bytes except last
      for (let j = 0; j < tempBytes.length - 1; j++) {
        bytes.push(tempBytes[j] | 0x80);
      }
      bytes.push(tempBytes[tempBytes.length - 1]);
    } else {
      bytes.push(value);
    }
    oidBytes.push(...bytes);
  }

  console.log(
    '\x1b[33m%s\x1b[0m',
    'OID bytes (hex):',
    oidBytes.map((b) => b.toString(16).padStart(2, '0')).join(' ')
  );

  // Search for OID in message
  // OID will be preceded by 0x06 (ASN.1 OID tag) and length byte
  for (let i = 0; i < message.length - oidBytes.length; i++) {
    if (message[i] === 0x06) {
      // OID tag
      const len = message[i + 1];
      if (len === oidBytes.length) {
        let found = true;
        for (let j = 0; j < len; j++) {
          if (message[i + 2 + j] !== oidBytes[j]) {
            found = false;
            break;
          }
        }
        if (found) {
          const result = {
            oid_index: i,
            oid_length: len + 2, // Add 2 for tag and length bytes
          };
          console.log('\x1b[32m%s\x1b[0m', 'Found OID at:', result); // Green color
          return result;
        }
      }
    }
  }

  throw new Error('OID not found in message');
}

export function generateCircuitInputsDSC(
  dscSecret: string,
  dscCertificate: any,
  max_cert_bytes: number,
  devMode: boolean = false
) {
  const dscCert = getCertificateFromPem(dscCertificate);
  const dscTbs = dscCert.tbsView;
  const dscTbsCertUint8Array = Uint8Array.from(
    dscTbs.map((byte) => parseInt(byte.toString(16), 16))
  );

  const {
    signatureAlgorithm,
    hashAlgorithm,
    publicKeyDetails,
    authorityKeyIdentifier,
    publicKeyAlgoOID,
  } = parseCertificate(dscCertificate, 'dsc_cert');

  const { bits, x, y, modulus, exponent, curve } = publicKeyDetails;

  let dsc_message_padded;
  let dsc_messagePaddedLen;
  [dsc_message_padded, dsc_messagePaddedLen] =
    hashAlgorithm == 'sha384' || hashAlgorithm == 'sha512'
      ? sha384_512Pad(dscTbsCertUint8Array, max_cert_bytes)
      : shaPad(dscTbsCertUint8Array, max_cert_bytes);

  // const { n, k } = getNAndK(`${signatureAlgorithm}_${hashAlgorithm}_${exponent}_${bits}` as SignatureAlgorithm);
  //dsc key is padded to 525 bytes
  const n = 8;
  const k = 525;
  const dscSignature = dscCert.signatureValue.valueBlock.valueHexView;
  const sigantureRaw = Array.from(forge.util.createBuffer(dscSignature).getBytes(), (char) =>
    char.charCodeAt(0)
  );

  let pubKey_dsc,
    signature,
    startIndex,
    dsc_message_padded_formatted,
    dsc_messagePaddedLen_formatted: any;
  let oidData;

  const sigAlgIndex = SignatureAlgorithmIndex[`${signatureAlgorithm}_${hashAlgorithm}_${exponent || curve}_${bits}` as keyof typeof SignatureAlgorithmIndex]

  if (signatureAlgorithm === 'rsa' || signatureAlgorithm === 'rsapss') {
    startIndex = findStartIndex(modulus, dsc_message_padded).toString();
    oidData = findOIDPosition(publicKeyAlgoOID, dsc_message_padded);

    dsc_message_padded_formatted = Array.from(dsc_message_padded).map((x) => x.toString());
    dsc_messagePaddedLen_formatted = BigInt(dsc_messagePaddedLen).toString();
    console.log('\x1b[34m', 'startIndex: ', startIndex, '\x1b[0m');
    console.log('\x1b[34m', 'n and k: ', n, k, '\x1b[0m');

    // const pubKey_dsc_1 = formatInput(splitToWords(BigInt(hexToDecimal(modulus)), n, k));
    // const pubkey_dsc_2 = formatInput(splitToWords(BigInt(0), n, k));

    // pubKey_dsc = [...pubKey_dsc_1, ...pubkey_dsc_2];
    pubKey_dsc = formatInput(splitToWords(BigInt(hexToDecimal(modulus)), n, k));
  } else if (signatureAlgorithm === 'ecdsa') {
    oidData = findOIDPosition(publicKeyAlgoOID, dsc_message_padded);

    const normalizedX = x.length % 2 === 0 ? x : '0' + x;
    const normalizedY = y.length % 2 === 0 ? y : '0' + y;
    console.log('\x1b[34m', 'n and k: ', n, k, '\x1b[0m');

    console.log('\x1b[34m', 'pubKey_dsc: ', pubKey_dsc, '\x1b[0m');

    const fullPubKey = normalizedX + normalizedY;
    pubKey_dsc = splitToWords(BigInt(hexToDecimal(fullPubKey)), 8, 525);
    const pubKeyBytes = Buffer.from(fullPubKey, 'hex');
    startIndex = findStartIndexEC(pubKeyBytes.toString('hex'), dsc_message_padded).toString();
    console.log('\x1b[34m', 'startIndex: ', startIndex, '\x1b[0m');

    dsc_message_padded_formatted = Array.from(dsc_message_padded).map((x) => x.toString());
    dsc_messagePaddedLen_formatted = BigInt(dsc_messagePaddedLen).toString();
  }
  console.log('authorityKeyIdentifier: ', authorityKeyIdentifier);
  const cscaPem = getCSCAFromSKI(authorityKeyIdentifier, devMode);
  console.log('\x1b[34m', 'cscaPem: ', cscaPem, '\x1b[0m');
  const leaf = getLeafCSCA(cscaPem);
  const [root, proof] = getCSCAModulusProof(leaf);

  const parsedCSCAPem = parseCertificate(cscaPem, 'csca_cert');
  let csca_pubKey_formatted;
  if (parsedCSCAPem.signatureAlgorithm === 'rsa' || parsedCSCAPem.signatureAlgorithm === 'rsapss') {
    const csca_modulus = parsedCSCAPem.publicKeyDetails.modulus;
    const { n: n_csca, k: k_csca } = getNAndK(
      `${parsedCSCAPem.signatureAlgorithm}_${parsedCSCAPem.hashAlgorithm}_${exponent}_${parsedCSCAPem.publicKeyDetails.bits}` as SignatureAlgorithm
    );
    // const { n: n_csca, k: k_csca } = getNAndKCSCA(parsedCSCAPem.signatureAlgorithm);
    console.log('\x1b[34m', 'n_csca: ', n_csca, 'k_csca: ', k_csca, '\x1b[0m');

    csca_pubKey_formatted = splitToWords(BigInt(hexToDecimal(csca_modulus)), n_csca, k_csca);
    signature = formatInput(splitToWords(BigInt(bytesToBigDecimal(sigantureRaw)), n_csca, k_csca));
  } else {
    console.log('\x1b[34m', 'signatureAlgorithm: ', parsedCSCAPem.signatureAlgorithm, '\x1b[0m');
    const { n: n_csca, k: k_csca } = getNAndK(
      `${parsedCSCAPem.signatureAlgorithm}_${parsedCSCAPem.hashAlgorithm}_${curve}_${parsedCSCAPem.publicKeyDetails.bits}` as SignatureAlgorithm
    );
    console.log('\x1b[34m', 'n_csca: ', n_csca, 'k_csca: ', k_csca, '\x1b[0m');

    const normalizedX =
      parsedCSCAPem.publicKeyDetails.x.length % 2 === 0
        ? parsedCSCAPem.publicKeyDetails.x
        : '0' + parsedCSCAPem.publicKeyDetails.x;
    const normalizedY =
      parsedCSCAPem.publicKeyDetails.y.length % 2 === 0
        ? parsedCSCAPem.publicKeyDetails.y
        : '0' + parsedCSCAPem.publicKeyDetails.y;
    const csca_x_formatted = splitToWords(BigInt(hexToDecimal(normalizedX)), n_csca, k_csca);
    const csca_y_formatted = splitToWords(BigInt(hexToDecimal(normalizedY)), n_csca, k_csca);
    csca_pubKey_formatted = [...csca_x_formatted, ...csca_y_formatted];

    const { r, s } = extractRSFromSignature(sigantureRaw);
    const signature_r = splitToWords(BigInt(hexToDecimal(r)), n_csca, k_csca);
    const signature_s = splitToWords(BigInt(hexToDecimal(s)), n_csca, k_csca);
    signature = [...signature_r, ...signature_s];
  }

  console.log('dsc_pubKey_length', pubKey_dsc.length);
  return {
    signature_algorithm: `${signatureAlgorithm}_${curve || exponent}_${hashAlgorithm}_${bits}`,
    inputs: {
      raw_dsc_cert: dsc_message_padded_formatted,
      raw_dsc_cert_padded_bytes: [dsc_messagePaddedLen_formatted],
      dsc_pubkey_length_bytes: signatureAlgorithm === 'ecdsa' ? [(bits / 8) * 2] : [bits / 8],
      csca_pubKey: csca_pubKey_formatted,
      signature: signature,
      dsc_pubKey_bytes: pubKey_dsc,
      dsc_pubKey_offset: [startIndex],
      merkle_root: [BigInt(root).toString()],
      path: proof.pathIndices.map((index) => index.toString()),
      siblings: proof.siblings.flat().map((sibling) => sibling.toString()),
      salt: dscSecret,
      signatureAlgorithm_dsc: sigAlgIndex
    },
  };
}

export function getCSCAFromSKI(ski: string, devMode: boolean): string {
  const normalizedSki = ski.replace(/\s+/g, '').toLowerCase();

  const cscaPemPROD = (SKI_PEM as any)[normalizedSki];
  const cscaPemDEV = (SKI_PEM_DEV as any)[normalizedSki];

  let cscaPem = devMode ? cscaPemDEV || cscaPemPROD : cscaPemPROD;

  if (!cscaPem) {
    console.log('\x1b[33m%s\x1b[0m', `[WRN] CSCA with SKI ${ski} not found`, 'devMode: ', devMode);
    throw new Error(
      `CSCA not found, authorityKeyIdentifier: ${ski}, areMockPassportsAllowed: ${devMode}`
    );
  }

  if (!cscaPem.includes('-----BEGIN CERTIFICATE-----')) {
    cscaPem = `-----BEGIN CERTIFICATE-----\n${cscaPem}\n-----END CERTIFICATE-----`;
  }

  return cscaPem;
}

export function derToBytes(derValue: string) {
  const bytes = [];
  for (let i = 0; i < derValue.length; i++) {
    bytes.push(derValue.charCodeAt(i));
  }
  return bytes;
}

export function getCSCAModulusMerkleTree() {
  const tree = new IMT(poseidon2, CSCA_TREE_DEPTH, 0, 2);
  tree.setNodes(serialized_csca_tree);
  return tree;
}

export function getCSCAModulusProof(leaf) {
  console.log('leaf', leaf);
  let tree = new IMT(poseidon2, CSCA_TREE_DEPTH, 0, 2);
  tree.setNodes(serialized_csca_tree);
  const index = tree.indexOf(leaf);
  if (index === -1) {
    throw new Error('Your public key was not found in the registry');
  }
  const proof = tree.createProof(index);
  return [tree.root, proof];
}

export function getTBSHash(
  cert: forge.pki.Certificate,
  hashFunction: 'sha1' | 'sha256',
  n: number,
  k: number
): string[] {
  const tbsCertAsn1 = forge.pki.certificateToAsn1(cert).value[0];
  const tbsCertDer = forge.asn1.toDer(tbsCertAsn1 as any).getBytes();
  const md = hashFunction === 'sha256' ? forge.md.sha256.create() : forge.md.sha1.create();
  md.update(tbsCertDer);
  const tbsCertificateHash = md.digest();
  const tbsCertificateHashString = tbsCertificateHash.data;
  const tbsCertificateHashHex = Buffer.from(tbsCertificateHashString, 'binary').toString('hex');
  const tbsCertificateHashBigint = BigInt(`0x${tbsCertificateHashHex}`);
  console.log('tbsCertificateHashBigint', tbsCertificateHashBigint);
  return splitToWords(tbsCertificateHashBigint, n, k);
}

export const sendCSCARequest = async (inputs_csca: any): Promise<any> => {
  try {
    const response = await axios.post(MODAL_SERVER_ADDRESS, inputs_csca, {
      headers: {
        'Content-Type': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      console.error('Axios error:', error.message);
      if (error.response) {
        console.error('Response data:', error.response.data);
        console.error('Response status:', error.response.status);
      }
    } else {
      console.error('Unexpected error:', error);
    }
    throw error;
  }
};

export const generateDscSecret = () => {
  const secretBytes = forge.random.getBytesSync(31);
  return BigInt(`0x${forge.util.bytesToHex(secretBytes)}`).toString();
};

function getCertificateFromPem(pemContent: string): Certificate {
  const certBuffer = Buffer.from(
    pemContent.replace(/(-----(BEGIN|END) CERTIFICATE-----|\n)/g, ''),
    'base64'
  );
  const asn1Data = asn1.fromBER(certBuffer);
  return new Certificate({ schema: asn1Data.result });
}
