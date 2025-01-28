import { max_dsc_bytes, max_csca_bytes, SignatureAlgorithmIndex } from '../constants/constants';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { poseidon2 } from 'poseidon-lite';
import { getTBSBytes, parseCertificateSimple } from './certificate_parsing/parseCertificateSimple';
import {
  PublicKeyDetailsECDSA,
  PublicKeyDetailsRSA,
} from './certificate_parsing/dataStructure';
import { SignatureAlgorithm } from './types';
import { getNAndK, getNAndKCSCA, pad } from './passports/passport';
import { splitToWords } from './bytes';
import { hexToDecimal } from './bytes';
import { customHasher, packBytesAndPoseidon } from './hash';

export function getLeaf(dsc: string): string {
  const { signatureAlgorithm, publicKeyDetails, hashAlgorithm } = parseCertificateSimple(dsc);

  if (signatureAlgorithm === 'ecdsa') {
    const { x, y, curve, bits } = publicKeyDetails as PublicKeyDetailsECDSA;
    const sigAlgKey = `${signatureAlgorithm}_${hashAlgorithm}_${curve}_${bits}`;
    const { n, k } = getNAndK(sigAlgKey as SignatureAlgorithm);
    console.log('sigAlgKey: ', sigAlgKey);
    console.log('getLeaf n: ', n);
    console.log('getLeaf k: ', k);
    const sigAlgIndex = SignatureAlgorithmIndex[sigAlgKey];

    if (sigAlgIndex == undefined) {
      console.error(`\x1b[31mInvalid signature algorithm: ${sigAlgKey}\x1b[0m`);
      throw new Error(`Invalid signature algorithm: ${sigAlgKey}`);
    }
    let qx = splitToWords(BigInt(hexToDecimal(x)), n, k);
    let qy = splitToWords(BigInt(hexToDecimal(y)), n, k);
    return customHasher([sigAlgIndex, ...qx, ...qy]);
  } else {
    const { modulus, bits, exponent } = publicKeyDetails as PublicKeyDetailsRSA;
    const sigAlgKey = `${signatureAlgorithm}_${hashAlgorithm}_${exponent}_${bits}`;
    const { n, k } = getNAndK(sigAlgKey as SignatureAlgorithm);
    const pubkeyChunked = splitToWords(BigInt(hexToDecimal(modulus)), n, k);

    const sigAlgIndex = SignatureAlgorithmIndex[sigAlgKey];
    if (sigAlgIndex == undefined) {
      console.error(`\x1b[31mInvalid signature algorithm: ${sigAlgKey}\x1b[0m`);
      throw new Error(`Invalid signature algorithm: ${sigAlgKey}`);
    }
    return customHasher([sigAlgIndex, ...pubkeyChunked]);
  }
}

export function getLeafCSCA(dsc: string): string {
  // Convert PEM certificate string to bytes array
  // const tbsBytes = getTBSBytes(cscaPem);
  // const [raw_csca_padded, raw_csca_actual_length] = pad("sha256")( // TODO: fix this
  //   tbsBytes,
  //   max_csca_bytes
  // );
  // // Pack bytes and hash with poseidon
  // return packBytesAndPoseidon(Array.from(raw_csca_padded).map(x => Number(x)));

  const parsedCertificate = parseCertificateSimple(dsc);

  const { signatureAlgorithm, hashAlgorithm } = parsedCertificate;

  const { publicKeyDetails } = parsedCertificate;

  const { n, k } = getNAndK(signatureAlgorithm as any);

  if (signatureAlgorithm === 'ecdsa') {
    const { x, y, bits, curve } = publicKeyDetails as PublicKeyDetailsECDSA;
    const { n, k } = getNAndK(`${signatureAlgorithm}_${hashAlgorithm}_${curve}_${bits}` as SignatureAlgorithm);

    let qx = splitToWords(BigInt(hexToDecimal(x)), n, k);
    let qy = splitToWords(BigInt(hexToDecimal(y)), n, k);
    return customHasher([...qx, ...qy]);
  } else {
    const { modulus, exponent } = publicKeyDetails as PublicKeyDetailsRSA;
    const { n, k } = getNAndK(`${signatureAlgorithm}_${hashAlgorithm}_${exponent}` as SignatureAlgorithm);


    const pubkeyChunked = splitToWords(BigInt(hexToDecimal(modulus)), n, k);
    return customHasher([...pubkeyChunked]);
  }
}

export async function fetchTreeFromUrl(url: string): Promise<LeanIMT> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const commitmentMerkleTree = await response.json();
  console.log('\x1b[90m%s\x1b[0m', 'commitment merkle tree: ', commitmentMerkleTree);
  const tree = LeanIMT.import((a, b) => poseidon2([a, b]), commitmentMerkleTree);
  return tree;
}
