import * as fs from 'fs';
import * as path from 'path';

export async function extractMasterlistDsc() {
  // Extract pem certificates from ldif file
  const ldif_path = path.join(__dirname, '..', '..', 'inputs', 'icao_download_section', 'dsc.ldif');
  const pem_path = path.join(__dirname, '..', '..', 'outputs', 'dsc', 'pem_masterlist');

  const fileContent = fs.readFileSync(ldif_path, "utf-8");
  const regex = /userCertificate;binary::\s*([\s\S]*?)(?=\w+:|\n\n|$)/g;
  let match: RegExpExecArray | null;

  const certificates: string[] = [];

  while ((match = regex.exec(fileContent)) !== null) {
    const certificate = match[1].replace(/\s+/g, "");
    certificates.push(certificate);
  }

  if (!fs.existsSync(pem_path)) {
    fs.mkdirSync(pem_path);
  }

  for (let i = 0; i < certificates.length; i++) {
    fs.writeFileSync(
      path.join(pem_path, `certificate_${i}.pem`),
      `-----BEGIN CERTIFICATE-----\n${certificates[i]}\n-----END CERTIFICATE-----\n`
    );
  }

  console.log(`Extracted ${certificates.length} certificates.`);
}

extractMasterlistDsc();