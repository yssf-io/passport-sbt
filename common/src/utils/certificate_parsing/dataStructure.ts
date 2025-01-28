import { StandardCurve } from './curves';

export interface CertificateData {
  id: string;
  issuer: string;
  validity: {
    notBefore: string;
    notAfter: string;
  };
  subjectKeyIdentifier: string;
  authorityKeyIdentifier: string;
  signatureAlgorithm: string;
  hashAlgorithm: string;
  publicKeyDetails:
  | PublicKeyDetailsRSA
  | PublicKeyDetailsECDSA
  | PublicKeyDetailsRSAPSS
  | undefined;
  tbsBytes: Uint8Array | undefined;
  tbsBytesLength: string;
  rawPem: string;
  rawTxt: string;
  publicKeyAlgoOID?: string;
}

export interface PublicKeyDetailsRSA {
  modulus: string;
  exponent: string;
  bits: string;
}

export interface PublicKeyDetailsRSAPSS extends PublicKeyDetailsRSA {
  hashAlgorithm: string;
  mgf: string;
  saltLength: string;
}

export interface PublicKeyDetailsECDSA {
  x: string;
  y: string;
  curve: string;
  params: StandardCurve;
  bits: string;
}
