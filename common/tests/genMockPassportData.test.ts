import { assert, expect } from 'chai';
import { describe, it } from 'mocha';
import { genMockPassportData } from '../src/utils/passports/genMockPassportData';
import { PassportData, SignatureAlgorithm } from '../src/utils/types';
import { parsePassportData } from '../src/utils/passports/passport_parsing/parsePassportData';

const testCases = [
  { dgHashAlgo: 'sha1', eContentHashAlgo: 'sha1', sigAlg: 'rsa_sha1_65537_2048' },
  { dgHashAlgo: 'sha1', eContentHashAlgo: 'sha1', sigAlg: 'rsa_sha256_65537_2048' },
  { dgHashAlgo: 'sha256', eContentHashAlgo: 'sha256', sigAlg: 'rsapss_sha256_65537_2048' },
  { dgHashAlgo: 'sha256', eContentHashAlgo: 'sha256', sigAlg: 'ecdsa_sha256_secp256r1_256' },
  { dgHashAlgo: 'sha256', eContentHashAlgo: 'sha256', sigAlg: 'ecdsa_sha256_brainpoolP256r1_256' },
  { dgHashAlgo: 'sha1', eContentHashAlgo: 'sha1', sigAlg: 'ecdsa_sha1_secp256r1_256' },
];


describe('Mock Passport Data Generator', function () {
  this.timeout(0);

  testCases.forEach(({ dgHashAlgo, eContentHashAlgo, sigAlg }) => {
    it(`should generate valid passport data for ${sigAlg}`, () => {
      const passportData = genMockPassportData(
        dgHashAlgo,
        eContentHashAlgo,
        sigAlg as SignatureAlgorithm,
        'FRA',
        '000101',
        '300101'
      );
      expect(verify(passportData, dgHashAlgo, eContentHashAlgo, sigAlg)).to.be.true;
    });
  });
});

function verify(
  passportData: PassportData,
  dgHashAlgo: string,
  eContentHashAlgo: string,
  sigAlg: string
): boolean {
  const passportMetaData = parsePassportData(passportData);
  // console.log('passportMetaData', passportMetaData);

  expect(passportMetaData.dg1HashFunction).to.equal(dgHashAlgo);
  expect(passportMetaData.eContentHashFunction).to.equal(eContentHashAlgo);

  // regex to find the signature algorithm (ecdsa or rsa/rsapss) before first underscore
  const signatureAlgorithm = sigAlg.match(/^([^_]+)/)?.[1];

  expect(passportMetaData.signatureAlgorithm).to.equal(signatureAlgorithm);

  return true;
}
