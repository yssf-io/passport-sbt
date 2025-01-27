import { SignatureAlgorithmIndex } from '../constants/constants';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { poseidon2 } from 'poseidon-lite';
import { parseCertificateSimple } from './certificate_parsing/parseCertificateSimple';
import {
  PublicKeyDetailsECDSA,
  PublicKeyDetailsRSA,
} from './certificate_parsing/dataStructure';
import { SignatureAlgorithm } from './types';
import { getNAndK, getNAndKCSCA } from './passports/passport';
import { splitToWords } from './bytes';
import { hexToDecimal } from './bytes';
import { customHasher } from './hash';


export function getLeaf(dsc: string): string {
  const { signatureAlgorithm, publicKeyDetails, hashAlgorithm } = parseCertificateSimple(dsc);

  if (signatureAlgorithm === 'ecdsa') {
    const { x, y, curve, bits } = publicKeyDetails as PublicKeyDetailsECDSA;
    const sigAlgKey = `${signatureAlgorithm}_${hashAlgorithm}_${curve}_${bits}`;
    const { n, k } = getNAndK(sigAlgKey as SignatureAlgorithm);
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
  const parsedCertificate = parseCertificateSimple(dsc);

  const signatureAlgorithm = parsedCertificate.signatureAlgorithm;

  const { publicKeyDetails } = parsedCertificate;

  const { n, k } = getNAndKCSCA(signatureAlgorithm as any);

  if (signatureAlgorithm === 'ecdsa') {
    const { x, y } = publicKeyDetails as PublicKeyDetailsECDSA;
    let qx = splitToWords(BigInt(hexToDecimal(x)), n, k);
    let qy = splitToWords(BigInt(hexToDecimal(y)), n, k);
    return customHasher([...qx, ...qy]);
  } else {
    const { modulus } = publicKeyDetails as PublicKeyDetailsRSA;

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
