import { PassportData } from '../../types';
import { parseCertificateSimple } from '../../certificate_parsing/parseCertificateSimple';
import { PublicKeyDetailsECDSA } from '../../certificate_parsing/dataStructure';
import forge, { md } from 'node-forge';
import * as asn1js from 'asn1js';
import { initElliptic } from '../../certificate_parsing/elliptic';
import { getCurveForElliptic } from '../../certificate_parsing/curves';
import { Certificate } from 'pkijs';
import { hashAlgos, saltLengths } from '../../../constants/constants';
import { hash } from '../../hash';

export function brutforceSignatureAlgorithm(passportData: PassportData) {
  const parsedDsc = parseCertificateSimple(passportData.dsc);
  if (parsedDsc.signatureAlgorithm === 'ecdsa') {
    const hashAlgorithm = brutforceHashAlgorithm(passportData, 'ecdsa');
    return {
      signatureAlgorithm: 'ecdsa',
      hashAlgorithm: hashAlgorithm,
      saltLength: 0,
    };
  } else if (parsedDsc.signatureAlgorithm === 'rsa') {
    const hashAlgorithm = brutforceHashAlgorithm(passportData, 'rsa');
    if (hashAlgorithm) {
      return {
        signatureAlgorithm: 'rsa',
        hashAlgorithm: hashAlgorithm,
        saltLength: 0,
      };
    }
  }
  // it's important to not put 'else if' statement here, because a rsapss signature can use rsa key certificate.
  for (const saltLength of saltLengths) {
    const hashAlgorithm = brutforceHashAlgorithm(passportData, 'rsapss', saltLength);
    if (hashAlgorithm) {
      return {
        signatureAlgorithm: 'rsapss',
        hashAlgorithm: hashAlgorithm,
        saltLength: saltLength,
      };
    }
  }
}

function brutforceHashAlgorithm(
  passportData: PassportData,
  signatureAlgorithm: string,
  saltLength?: number
): any {
  for (const hashFunction of hashAlgos) {
    if (verifySignature(passportData, signatureAlgorithm, hashFunction, saltLength)) {
      return hashFunction;
    }
  }
  return false;
}

export function verifySignature(
  passportData: PassportData,
  signatureAlgorithm: string,
  hashAlgorithm: string,
  saltLength: number = 0
): boolean {
  switch (signatureAlgorithm) {
    case 'ecdsa':
      return verifyECDSA(passportData, hashAlgorithm);
    case 'rsa':
      return verifyRSA(passportData, hashAlgorithm);
    case 'rsapss':
      return verifyRSAPSS(passportData, hashAlgorithm, saltLength);
  }
}

function verifyECDSA(passportData: PassportData, hashAlgorithm: string) {
  const elliptic = initElliptic();
  const { dsc, signedAttr, encryptedDigest } = passportData;
  const { publicKeyDetails } = parseCertificateSimple(dsc);
  const certBuffer = Buffer.from(
    dsc.replace(/(-----(BEGIN|END) CERTIFICATE-----|\n)/g, ''),
    'base64'
  );
  const asn1Data = asn1js.fromBER(certBuffer);
  const cert = new Certificate({ schema: asn1Data.result });
  const publicKeyInfo = cert.subjectPublicKeyInfo;
  const publicKeyBuffer = publicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
  const curveForElliptic = getCurveForElliptic((publicKeyDetails as PublicKeyDetailsECDSA).curve);
  const ec = new elliptic.ec(curveForElliptic);

  const key = ec.keyFromPublic(publicKeyBuffer);
  const msgHash = hash(hashAlgorithm, signedAttr, 'hex');
  const signature_crypto = Buffer.from(encryptedDigest).toString('hex');

  return key.verify(msgHash, signature_crypto);
}

function verifyRSA(passportData: PassportData, hashAlgorithm: string) {
  const { dsc, signedAttr, encryptedDigest } = passportData;
  const cert = forge.pki.certificateFromPem(dsc);
  const publicKey = cert.publicKey as forge.pki.rsa.PublicKey;
  const msgHash = hash(hashAlgorithm, signedAttr, 'binary');
  const signature = Buffer.from(encryptedDigest).toString('binary');
  try {
    return publicKey.verify(msgHash as string, signature);
  } catch (error) {
    return false;
  }
}

function verifyRSAPSS(passportData: PassportData, hashAlgorithm: string, saltLength: number) {
  const { dsc, signedAttr, encryptedDigest } = passportData;
  const cert = forge.pki.certificateFromPem(dsc);
  const publicKey = cert.publicKey as forge.pki.rsa.PublicKey;
  const msgHash = hash(hashAlgorithm, signedAttr, 'binary');

  const signature = Buffer.from(encryptedDigest).toString('binary');
  if (saltLength === 0) {
    throw new Error('Salt length is required for RSA-PSS');
  }
  try {
    const pss = forge.pss.create({
      md: forge.md[hashAlgorithm].create(),
      mgf: forge.mgf.mgf1.create(forge.md[hashAlgorithm].create()),
      saltLength: saltLength,
    });
    return publicKey.verify(msgHash as string, signature, pss);
  } catch (error) {
    return false;
  }
}
