import fs from 'fs';
import { execSync } from 'child_process';
import { parseCertificateSimple } from './parseCertificateSimple';
import { CertificateData } from './dataStructure';
export function parseCertificate(pem: string, fileName: string): CertificateData {
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
    tbsBytes: undefined,
    tbsBytesLength: '',
    rawPem: '',
    rawTxt: '',
    publicKeyAlgoOID: '',
  };
  try {
    certificateData = parseCertificateSimple(pem);
    const baseFileName = fileName.replace('.pem', '');
    const tempCertPath = `/tmp/${baseFileName}.pem`;

    const formattedPem = pem.includes('-----BEGIN CERTIFICATE-----')
      ? pem
      : `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;

    fs.writeFileSync(tempCertPath, formattedPem);
    try {
      const openSslOutput = execSync(`openssl x509 -in ${tempCertPath} -text -noout`).toString();
      certificateData.rawTxt = openSslOutput;
    } catch (error) {
      console.error(`Error executing OpenSSL command: ${error}`);
      certificateData.rawTxt = 'Error: Unable to generate human-readable format';
    } finally {
      try {
        fs.unlinkSync(tempCertPath);
      } catch (e) {
        // Ignore cleanup errors
      }
    }

    return certificateData;
  } catch (error) {
    console.error(`Error processing certificate ${fileName}:`, error);
    throw error;
  }
}
