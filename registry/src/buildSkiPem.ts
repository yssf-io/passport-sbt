import fs from 'fs';
import path from 'path';
import { parseCertificateSimple } from '../../common/src/utils/certificate_parsing/parseCertificateSimple';
import { parseCertificate } from '../../common/src/utils/certificate_parsing/parseCertificate';
import { CertificateData } from '../../common/src/utils/certificate_parsing/dataStructure';
import { DEVELOPMENT_MODE } from '../../common/src/constants/constants';

const pemDirectory = path.join(__dirname, '..', 'outputs', 'csca', 'pem_masterlist');
const ski_pem_path = path.join(__dirname, '..', 'outputs', 'ski_pem.json');
const ski_pem_dev_path = path.join(__dirname, '..', 'outputs', 'ski_pem_dev.json');
const dev_pem_path = path.join(__dirname, '..', '..', 'common', 'src', 'mock_certificates');

function cleanCertificate(certContent: string): string {
    return certContent
        .replace(/[\r\n]/g, '')
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '');
}

async function getAllDevPem() {
    let certificates: string[] = [];
    const subdirectories = fs.readdirSync(dev_pem_path, { withFileTypes: true })
        .filter(item => item.isDirectory())
        .map(item => item.name);
    for (const subdirectory of subdirectories) {
        const pemFilePath = path.join(dev_pem_path, subdirectory, 'mock_csca.pem');
        if (fs.existsSync(pemFilePath)) {
            const pemFile = cleanCertificate(fs.readFileSync(pemFilePath, 'utf8'));
            certificates.push(pemFile);
        }
        const cerFilePath = path.join(dev_pem_path, subdirectory, 'mock_csca.cer');
        if (fs.existsSync(cerFilePath)) {
            const cerFile = cleanCertificate(fs.readFileSync(cerFilePath, 'utf8'));
            certificates.push(cerFile);
        }
    }
    return certificates;
}

async function main() {
    const skiPemDevJson: {
        [key: string]: string
    } = {};
    const skiPemJson: {
        [key: string]: string
    } = {};

    const devCertificates = await getAllDevPem();
    const prodCertificates = fs.readdirSync(pemDirectory);

    if (!DEVELOPMENT_MODE) {
        for (const prodCertificate of prodCertificates) {
            const pemContent = cleanCertificate(fs.readFileSync(path.join(pemDirectory, prodCertificate), 'utf8'));
            //log filename
            console.log('\x1b[90m%s\x1b[0m', `processing ${prodCertificate}`);
            try {
                const certificateData = parseCertificateSimple(pemContent);



                skiPemJson[certificateData.subjectKeyIdentifier] = pemContent;
            } catch (error) {
                console.log('\x1b[90m%s\x1b[0m', `certificate ${prodCertificate} is invalid.`);
            }
        }
    }

    for (const devCertificate of devCertificates) {
        try {
            const certificateData = parseCertificateSimple(devCertificate);
            skiPemDevJson[certificateData.subjectKeyIdentifier] = devCertificate;


        } catch (error) {
            console.log('\x1b[90m%s\x1b[0m', `certificate ${devCertificate} is invalid.`);
        }
    }

    fs.writeFileSync(ski_pem_path, JSON.stringify(skiPemJson, null, 2));
    fs.writeFileSync(ski_pem_dev_path, JSON.stringify(skiPemDevJson, null, 2));

}

main().catch(console.error);
