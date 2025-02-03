import * as forge from 'node-forge';
import * as fs from 'fs';
import { MODAL_SERVER_ADDRESS } from '../constants/constants';
import axios from 'axios';
import { SKI_PEM, SKI_PEM_DEV } from '../constants/skiPem';
import { splitToWords } from './bytes';
import path from 'path';

export function findStartIndexEC(modulus: string, messagePadded: Uint8Array): [number, number] {
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
  return [startIndex, modulusNumArray.length];
}

// @returns [startIndex, length] where startIndex is the index of the first byte of the modulus in the message and length is the length of the modulus in bytes
export function findStartIndex(modulus: string, messagePadded: Uint8Array): [number, number] {
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
      return [i, modulusNumArray.length];
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
  // console.log('tbsCertificateHashBigint', tbsCertificateHashBigint);
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

export function getCsca(signatureAlgorith: string) {
  return fs.readFileSync(path.join(__dirname, `../mock_certificates/${signatureAlgorith}/mock_csca.pem`), 'base64');
}