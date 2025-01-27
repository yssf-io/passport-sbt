import * as asn1js from 'asn1js';
import { Certificate, RSAPublicKey, RSASSAPSSParams } from 'pkijs';
import { getFriendlyName } from './oids';
import {
  CertificateData,
  PublicKeyDetailsECDSA,
  PublicKeyDetailsRSA,
  PublicKeyDetailsRSAPSS,
} from './dataStructure';
import { getCurveForElliptic, getECDSACurveBits, identifyCurve, StandardCurve } from './curves';
import { getIssuerCountryCode, getSubjectKeyIdentifier } from './utils';
import { circuitNameFromMode } from '../../constants/constants';
import { Mode } from '../appType';
import { initElliptic } from './elliptic';

export function parseCertificateSimple(pem: string): CertificateData {
  let certificateData: CertificateData = {
    id: '',
    issuer: '',
    validity: {
      notBefore: '',
      notAfter: '',
    },
    subjectKeyIdentifier: '',
    authorityKeyIdentifier: '',
    signatureAlgorithm: '',
    hashAlgorithm: '',
    publicKeyDetails: undefined,
    rawPem: '',
    rawTxt: '',
    publicKeyAlgoOID: '',
  };
  try {
    const pemFormatted = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|\n|\r)/g, '');
    const binary = Buffer.from(pemFormatted, 'base64');
    const arrayBuffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(arrayBuffer);
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary[i];
    }

    const asn1 = asn1js.fromBER(arrayBuffer);
    if (asn1.offset === -1) {
      throw new Error(`ASN.1 parsing error: ${asn1.result.error}`);
    }

    const cert = new Certificate({ schema: asn1.result });
    const publicKeyAlgoOID = cert.subjectPublicKeyInfo.algorithm.algorithmId;
    const publicKeyAlgoFN = getFriendlyName(publicKeyAlgoOID);
    const signatureAlgoOID = cert.signatureAlgorithm.algorithmId;
    const signatureAlgoFN = getFriendlyName(signatureAlgoOID);
    certificateData.hashAlgorithm = getHashAlgorithm(signatureAlgoFN);
    certificateData.publicKeyAlgoOID = publicKeyAlgoOID;
    let params;
    if (publicKeyAlgoFN === 'RSA') {
      certificateData.signatureAlgorithm = 'rsa';
      params = getParamsRSA(cert);
    } else if (publicKeyAlgoFN === 'ECC') {
      certificateData.signatureAlgorithm = 'ecdsa';
      params = getParamsECDSA(cert);
    } else if (publicKeyAlgoFN === 'RSASSA_PSS') {
      certificateData.signatureAlgorithm = 'rsapss';
      params = getParamsRSAPSS(cert);
    } else {
      console.log(publicKeyAlgoFN);
    }
    certificateData.publicKeyDetails = params;
    certificateData.issuer = getIssuerCountryCode(cert);
    certificateData.validity = {
      notBefore: cert.notBefore.value.toString(),
      notAfter: cert.notAfter.value.toString(),
    };
    const ski = getSubjectKeyIdentifier(cert);
    certificateData.id = ski.slice(0, 12);
    certificateData.subjectKeyIdentifier = ski;
    certificateData.rawPem = pem;

    const authorityKeyIdentifier = getAuthorityKeyIdentifier(cert);
    certificateData.authorityKeyIdentifier = authorityKeyIdentifier;

    // corner case for rsapss
    if (certificateData.signatureAlgorithm === 'rsapss' && !certificateData.hashAlgorithm) {
      certificateData.hashAlgorithm = (
        certificateData.publicKeyDetails as PublicKeyDetailsRSAPSS
      ).hashAlgorithm;
    }

    return certificateData;
  } catch (error) {
    console.error(`Error processing certificate`, error);
    throw error;
  }
}

function getParamsRSA(cert: Certificate): PublicKeyDetailsRSA {
  const publicKeyValue = cert.subjectPublicKeyInfo.parsedKey as RSAPublicKey;
  const modulusBytes = publicKeyValue.modulus.valueBlock.valueHexView;
  const modulusHex = Buffer.from(modulusBytes).toString('hex');
  const exponentBigInt = publicKeyValue.publicExponent.toBigInt();
  const exponentDecimal = exponentBigInt.toString();
  const actualBits = modulusBytes.length * 8;

  return {
    modulus: modulusHex,
    exponent: exponentDecimal,
    bits: actualBits.toString(),
  };
}

function getParamsRSAPSS(cert: Certificate): PublicKeyDetailsRSAPSS {
  // Get the subjectPublicKey BitString
  const spki = cert.subjectPublicKeyInfo;
  const spkiValueHex = spki.subjectPublicKey.valueBlock.valueHexView;

  // Parse the public key ASN.1 structure
  const asn1PublicKey = asn1js.fromBER(spkiValueHex);
  if (asn1PublicKey.offset === -1) {
    throw new Error('Error parsing public key ASN.1 structure');
  }

  // The public key is an RSAPublicKey structure
  const rsaPublicKey = new RSAPublicKey({ schema: asn1PublicKey.result });
  const modulusBytes = rsaPublicKey.modulus.valueBlock.valueHexView;
  const modulusHex = Buffer.from(modulusBytes).toString('hex');
  const exponentBigInt = rsaPublicKey.publicExponent.toBigInt();
  const exponentDecimal = exponentBigInt.toString();
  const actualBits = modulusBytes.length * 8;

  const sigAlgParams = cert.signatureAlgorithm.algorithmParams;
  const pssParams = new RSASSAPSSParams({ schema: sigAlgParams });
  const hashAlgorithm = getFriendlyName(pssParams.hashAlgorithm.algorithmId);
  const mgf = getFriendlyName(pssParams.maskGenAlgorithm.algorithmId);

  return {
    modulus: modulusHex,
    exponent: exponentDecimal,
    bits: actualBits.toString(),
    hashAlgorithm: hashAlgorithm,
    mgf: mgf,
    saltLength: pssParams.saltLength.toString(),
  };
}

export function getParamsECDSA(cert: Certificate): PublicKeyDetailsECDSA {
  try {
    const algorithmParams = cert.subjectPublicKeyInfo.algorithm.algorithmParams;

    if (!algorithmParams) {
      console.error('No algorithm params found');
      return {
        curve: 'Unknown',
        params: {} as StandardCurve,
        bits: 'Unknown',
        x: 'Unknown',
        y: 'Unknown',
      };
    }

    let curveName,
      bits,
      x,
      y = 'Unknown';
    let curveParams: StandardCurve = {} as StandardCurve;

    // Try to get the curve name from the OID
    if (algorithmParams instanceof asn1js.ObjectIdentifier) {
      const curveOid = algorithmParams.valueBlock.toString();
      curveName = getFriendlyName(curveOid) || 'Unknown';
      bits = getECDSACurveBits(curveName);
    }

    // If the OID of the curve is not present, we try to get the curve parameters and identify the curve from them
    else {
      const params = asn1js.fromBER(algorithmParams.valueBeforeDecodeView).result;
      const valueBlock: any = params.valueBlock;
      if (valueBlock.value && valueBlock.value.length >= 5) {
        const curveParams: StandardCurve = {} as StandardCurve;
        // Field ID (index 1)
        const fieldId = valueBlock.value[1];
        if (fieldId && fieldId.valueBlock && fieldId.valueBlock.value) {
          const fieldType = fieldId.valueBlock.value[0];
          const prime = fieldId.valueBlock.value[1];
          //curveParams.fieldType = fieldType.valueBlock.toString();
          curveParams.p = Buffer.from(prime.valueBlock.valueHexView).toString('hex');
        }

        // Curve Coefficients (index 2)
        const curveCoefficients = valueBlock.value[2];
        if (
          curveCoefficients &&
          curveCoefficients.valueBlock &&
          curveCoefficients.valueBlock.value
        ) {
          const a = curveCoefficients.valueBlock.value[0];
          const b = curveCoefficients.valueBlock.value[1];
          curveParams.a = Buffer.from(a.valueBlock.valueHexView).toString('hex');
          curveParams.b = Buffer.from(b.valueBlock.valueHexView).toString('hex');
        }

        // Base Point G (index 3)
        const basePoint = valueBlock.value[3];
        if (basePoint && basePoint.valueBlock) {
          curveParams.G = Buffer.from(basePoint.valueBlock.valueHexView).toString('hex');
        }

        // Order n (index 4)
        const order = valueBlock.value[4];
        if (order && order.valueBlock) {
          curveParams.n = Buffer.from(order.valueBlock.valueHexView).toString('hex');
        }

        if (valueBlock.value.length >= 6) {
          // Cofactor h (index 5)
          const cofactor = valueBlock.value[5];
          if (cofactor && cofactor.valueBlock) {
            curveParams.h = Buffer.from(cofactor.valueBlock.valueHexView).toString('hex');
          }
        } else {
          curveParams.h = '01';
        }
        const identifiedCurve = identifyCurve(curveParams);
        curveName = identifiedCurve;
        bits = getECDSACurveBits(curveName);
      } else {
        if (valueBlock.value) {
          console.log(valueBlock.value);
        } else {
          console.log('No value block found');
        }
      }
    }

    // Get the public key x and y parameters
    const publicKeyBuffer = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
    if (publicKeyBuffer && curveName !== 'Unknown') {
      const elliptic = initElliptic();
      const ec = new elliptic.ec(getCurveForElliptic(curveName));
      const key = ec.keyFromPublic(publicKeyBuffer);
      x = key.getPublic().getX().toString('hex');
      y = key.getPublic().getY().toString('hex');
    }
    return { curve: curveName, params: curveParams, bits: bits, x: x, y: y };
  } catch (error) {
    console.error('Error parsing EC parameters:', error);
    return {
      curve: 'Error',
      params: {} as StandardCurve,
      bits: 'Unknown',
      x: 'Unknown',
      y: 'Unknown',
    };
  }
}

export const getAuthorityKeyIdentifier = (cert: Certificate): string => {
  const authorityKeyIdentifier = cert.extensions.find((ext) => ext.extnID === '2.5.29.35');
  if (authorityKeyIdentifier) {
    let akiValue = Buffer.from(authorityKeyIdentifier.extnValue.valueBlock.valueHexView).toString(
      'hex'
    );
    akiValue = akiValue.replace(/^(?:3016)?(?:0414)?/, '');
    // cur off the first 2 bytes
    akiValue = akiValue.slice(4);
    return akiValue;
  }
  return null;
};

export const getCircuitName = (
  circuitMode: 'prove' | 'dsc' | 'vc_and_disclose',
  signatureAlgorithm: string,
  hashFunction: string,
  domainParameter: string,
  keyLength: string
) => {
  const circuit = circuitNameFromMode[circuitMode];
  if (circuit == 'vc_and_disclose') {
    return 'vc_and_disclose';
  }
  if (circuit == 'dsc') {
    return (
      circuit +
      '_' +
      signatureAlgorithm +
      '_' +
      hashFunction +
      '_' +
      domainParameter +
      '_' +
      keyLength
    );
  }
  return (
    circuit +
    '_' +
    signatureAlgorithm +
    '_' +
    hashFunction +
    '_' +
    domainParameter +
    '_' +
    keyLength
  );
};
export const getCircuitNameOld = (
  circuitMode: Mode,
  signatureAlgorithm: string,
  hashFunction: string
) => {
  const circuit = circuitNameFromMode[circuitMode];
  if (circuit == 'vc_and_disclose') {
    return 'vc_and_disclose';
  } else if (signatureAlgorithm === 'ecdsa') {
    return circuit + '_' + signatureAlgorithm + '_secp256r1_' + hashFunction;
  } else {
    return circuit + '_' + signatureAlgorithm + '_65537_' + hashFunction;
  }
};

export function getHashAlgorithm(rawSignatureAlgorithm: string) {
  const input = rawSignatureAlgorithm.toLowerCase();
  const patterns = [/sha-?1/i, /sha-?256/i, /sha-?384/i, /sha-?512/i];

  for (const pattern of patterns) {
    const match = input.match(pattern);
    if (match) {
      // Remove any hyphens and return standardized format
      return match[0].replace('-', '');
    }
  }

  return 'unknown';
}
