import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { poseidon2 } from 'poseidon-lite';
import {
  CertificateData,
} from './certificate_parsing/dataStructure';
import { packBytesAndPoseidon } from './hash';
import { parseDscCertificateData } from './passports/passport_parsing/parseDscCertificateData';
import { parseCertificateSimple } from './certificate_parsing/parseCertificateSimple';
import { max_csca_bytes } from '../constants/constants';
import { max_dsc_bytes } from '../constants/constants';

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

function getLeaf(parsed: CertificateData, type: 'dsc' | 'csca'): string {
  const maxPaddedLength = type === 'dsc' ? max_dsc_bytes : max_csca_bytes;
  const { tbsBytes, } = parsed;
  const tbsBytesArray = Array.from(tbsBytes);
  const paddedTbsBytesArray = tbsBytesArray.concat(new Array(maxPaddedLength - tbsBytesArray.length).fill(0));
  const tbsBytesHash = packBytesAndPoseidon(paddedTbsBytesArray);
  return tbsBytesHash;
}

export function getLeafDscTreeFromParsedDsc(dscParsed: CertificateData): string {
  const dscMetaData = parseDscCertificateData(dscParsed);
  const cscaParsed = parseCertificateSimple(dscMetaData.csca);
  return getLeafDscTree(dscParsed, cscaParsed);
}

export function getLeafDscTree(dsc_parsed: CertificateData, csca_parsed: CertificateData): string {
  const dscLeaf = getLeaf(dsc_parsed, 'dsc');
  const cscaLeaf = getLeaf(csca_parsed, 'csca');
  return poseidon2([dscLeaf, cscaLeaf]).toString();
}

export function getLeafCscaTree(csca_parsed: CertificateData): string {
  return getLeaf(csca_parsed, 'csca');
}
