import * as fs from 'fs';
import { getLeafDscTreeFromDscCertificateMetadata, getLeafDscTreeFromParsedDsc } from '../../../common/src/utils/trees';
import { DEVELOPMENT_MODE, DSC_TREE_DEPTH } from '../../../common/src/constants/constants';
import { IMT } from '@openpassport/zk-kit-imt';
import { poseidon2 } from 'poseidon-lite';
import { writeFile } from 'fs/promises';
import * as path from 'path';
import { parseCertificate } from '../../../common/src/utils/certificate_parsing/parseCertificate';
import { parseCertificateSimple } from '../../../common/src/utils/certificate_parsing/parseCertificateSimple';
import { parseDscCertificateData } from '../../../common/src/utils/passports/passport_parsing/parseDscCertificateData';
import { CertificateData, PublicKeyDetailsECDSA, PublicKeyDetailsRSA } from '../../../common/src/utils/certificate_parsing/dataStructure';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';

let tbs_max_bytes = 0;
let key_length_max_bytes = 0;
const countryKeyBitLengths: { [countryCode: string]: number } = {};
let cscaDescriptions: { [cscaDesciption: string]: number } = {};
let dscDescriptions: { [dscDescription: string]: number } = {};
let undefinedFilePathsCsca: string[] = [];
let undefinedFilePathsDsc: string[] = [];
let dscDescriptionsExtrapolated: { [dscDescription: string]: number } = {};
function processCertificate(pemContent: string, filePath: string) {
    try {
        const certificate: CertificateData = parseCertificateSimple(pemContent);
        if (parseInt(certificate.tbsBytesLength) > tbs_max_bytes) {
            tbs_max_bytes = parseInt(certificate.tbsBytesLength);
        }
        if (parseInt(certificate.publicKeyDetails.bits) > key_length_max_bytes) {
            key_length_max_bytes = parseInt(certificate.publicKeyDetails.bits);
        }
        const validAlgorithms = ['rsa', 'rsapss', 'ecdsa'];
        if (!validAlgorithms.includes(certificate.signatureAlgorithm)) {
            console.log(`Skipping file ${filePath}: Unsupported signature algorithm ${certificate.signatureAlgorithm}`);
            return null;
        }

        if (!certificate.publicKeyDetails) {
            console.log(`Skipping file ${filePath}: No public key details`);
            return null;
        }

        const keyLength = parseInt(certificate.publicKeyDetails.bits);
        if (keyLength > 4096) {
            countryKeyBitLengths[certificate.issuer] = keyLength;
            console.log(`Skipping file ${filePath}: Key length ${keyLength} bits exceeds 4096 bits`);
            return null;
        }

        console.log('\x1b[90mFile:', 'common/' + filePath.split('/common/')[1], '\x1b[0m');
        // console.log(`Key Length: ${keyLength} bits`);
        // console.log(`Signature Algorithm: ${certificate.signatureAlgorithm}`);
        // console.log(`Hash Algorithm: ${certificate.hashAlgorithm}`);
        // CSCA parsing
        const dscMetaData = parseDscCertificateData(certificate);
        // console.log('js: dscMetaData', dscMetaData);
        let cscaDesc = '';
        if (dscMetaData.cscaFound) {
            if (dscMetaData.cscaSignatureAlgorithm == 'ecdsa') {
                cscaDesc = `${dscMetaData.cscaHashAlgorithm}_${dscMetaData.cscaSignatureAlgorithm}_${dscMetaData.cscaCurveOrExponent}`;
            }
            else if (dscMetaData.cscaSignatureAlgorithm == 'rsapss') {
                cscaDesc = `${dscMetaData.cscaHashAlgorithm}_${dscMetaData.cscaSignatureAlgorithm}_${dscMetaData.cscaCurveOrExponent}_${dscMetaData.cscaSaltLength}_${dscMetaData.cscaBits}`;
            }
            else {
                cscaDesc = `${dscMetaData.cscaHashAlgorithm}_${dscMetaData.cscaSignatureAlgorithm}_${dscMetaData.cscaCurveOrExponent}_${dscMetaData.cscaBits}`;
            }
            if (cscaDesc.includes('undefined') || cscaDesc.includes('unknown')) {
                undefinedFilePathsCsca.push(filePath);
            }
        }
        cscaDescriptions[cscaDesc] = (cscaDescriptions[cscaDesc] || 0) + 1;

        // DSC parsing
        let dscDesc
        if (certificate.signatureAlgorithm == 'ecdsa') {
            dscDesc = `${certificate.hashAlgorithm}_${certificate.signatureAlgorithm}_${(certificate.publicKeyDetails as PublicKeyDetailsECDSA).curve}`;
        }
        else {
            dscDesc = `${certificate.hashAlgorithm}_${certificate.signatureAlgorithm}_${(certificate.publicKeyDetails as PublicKeyDetailsRSA).exponent}_${certificate.publicKeyDetails.bits}`;
        }
        if (dscDesc.includes('undefined') || dscDesc.includes('unknown')) {
            undefinedFilePathsDsc.push(filePath);
        }
        dscDescriptions[dscDesc] = (dscDescriptions[dscDesc] || 0) + 1;
        let dscDescExt
        // DSC Extrapolation
        if (certificate.signatureAlgorithm == 'ecdsa') {
            dscDescExt = `${certificate.hashAlgorithm}_${certificate.signatureAlgorithm}_${(certificate.publicKeyDetails as PublicKeyDetailsECDSA).curve}`;
        }
        else {
            if (dscMetaData.cscaSignatureAlgorithm == 'rsapss') {
                dscDescExt = `${certificate.hashAlgorithm}_${'rsapss'}_${(certificate.publicKeyDetails as PublicKeyDetailsRSA).exponent}_${dscMetaData.cscaSaltLength}_${certificate.publicKeyDetails.bits}`;
            }
            else {
                dscDescExt = `${certificate.hashAlgorithm}_${certificate.signatureAlgorithm}_${(certificate.publicKeyDetails as PublicKeyDetailsRSA).exponent}_${certificate.publicKeyDetails.bits}`;
            }
        }
        dscDescriptionsExtrapolated[dscDescExt] = (dscDescriptionsExtrapolated[dscDescExt] || 0) + 1;

        // Final Poseidon Hash
        const finalPoseidonHash = getLeafDscTreeFromDscCertificateMetadata(certificate, dscMetaData);
        console.log('Leaf Value: \x1b[34m' + finalPoseidonHash + '\x1b[0m');

        return finalPoseidonHash.toString();
    } catch (error) {
        console.error(`Error processing certificate ${filePath}:`, error);
        return null;
    }
}

async function buildDscMerkleTree() {
    const tree = new LeanIMT((a, b) => poseidon2([a, b]), []);

    if (!DEVELOPMENT_MODE) {
        const path_to_pem_files = "outputs/dsc/pem_masterlist";
        for (const file of fs.readdirSync(path_to_pem_files)) {
            const file_path = path.join(path_to_pem_files, file);
            try {
                const pemContent = fs.readFileSync(file_path, 'utf8');
                const leafValue = processCertificate(pemContent, file_path);
                if (leafValue) {
                    tree.insert(BigInt(leafValue));
                }
            } catch (error) {
                console.error(`Error reading file ${file}:`, error);
            }
        }
    }

    if (DEVELOPMENT_MODE) {
        const dev_pem_path = path.join(__dirname, '..', '..', '..', 'common', 'src', 'mock_certificates');
        const subdirectories = fs.readdirSync(dev_pem_path, { withFileTypes: true })
            .filter(item => item.isDirectory())
            .map(item => item.name);

        for (const subdirectory of subdirectories) {
            const pemFilePath = path.join(dev_pem_path, subdirectory, 'mock_dsc.pem');

            if (fs.existsSync(pemFilePath)) {
                try {
                    const pemContent = fs.readFileSync(pemFilePath, 'utf8');
                    const leafValue = processCertificate(pemContent, pemFilePath);
                    if (leafValue) {
                        tree.insert(BigInt(leafValue));
                    }
                } catch (error) {
                    console.error(`Error processing mock file ${pemFilePath}:`, error);
                }
            }
        }
    }
    logTree();
    console.log('Root Value:', '\x1b[35m' + tree.root + '\x1b[0m');

    // console.log(`Max TBS bytes: ${tbs_max_bytes}`);
    // console.log(`Max Key Length: ${key_length_max_bytes}`);
    // console.log('js: countryKeyBitLengths', countryKeyBitLengths);
    // console.log('js: cscaDescriptions', cscaDescriptions);
    // console.log('js: dscDescriptions', dscDescriptions);
    // console.log('js: dscDescriptionsExtrapolated', dscDescriptionsExtrapolated);
    console.log('\x1b[90mCSCA: Error parsing these files:', undefinedFilePathsCsca, '\x1b[0m');
    console.log('\x1b[90mDSC: Error parsing these files:', undefinedFilePathsDsc, '\x1b[0m');
    return tree;
}

async function serializeDscTree(tree: LeanIMT) {
    const serializedTree = tree.export();
    await writeFile("outputs/serialized_dsc_tree.json", JSON.stringify(serializedTree));
    fs.copyFileSync("outputs/serialized_dsc_tree.json", "../common/pubkeys/serialized_dsc_tree.json");
    console.log("\x1b[32mSerialized DSC tree written and copied in common/pubkeys.\x1b[0m");
}

async function main() {
    const tree = await buildDscMerkleTree();
    await serializeDscTree(tree);
}

main();

function logTree() {
    console.log(
        `\x1b[32m` +
        `
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠧⠒⠉⠁⠀⢀⠀⠀⠀⠀⣀⠔⠓⠂⠐⠊⢉⠤⢄⠠⠤⣈⡁⠒⠒⠚⠷⠖⠈⠉⡩⠥⡀⠉⠋⡗⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⡠⠊⢃⠀⠐⠋⢀⡀⠀⠀⢠⠔⠊⠀⠀⠀⠀⠀⠑⢄⠀⠀⠃⠀⠀⠞⠀⠀⠑⢄⠀⠃⠀⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠝⠂⠀⠀⠀⡠⠊⠁⠀⠈⡄⠀⠀⡇⠀⠑⠀⢸⠄⠀⠀⠀⠀⡠⠤⢀⠈⡀⠀⠲⠀⢰⠀⠀⠀⠀⠈⡧⢀⠀⠀⠀⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⠃⠀⠀⠀⠀⡐⠁⠀⠀⠀⠀⠠⠠⠊⠀⣀⣀⠄⠊⠀⠀⠀⠀⡜⠀⠀⠀⠑⢼⡀⠀⠀⡌⠀⠀⠀⠀⠀⢨⢄⠈⢢⣄⠀⠑⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⠞⠁⠀⠀⡠⠊⠉⢈⠠⠴⠊⢢⠀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠠⠋⠈⠁⠀⠀⠀⢀⠘⡈⢢⠜⠀⠀⠀⠀⠀⠀⠀⠑⠠⠈⠢⠑⠄⡀⠀⠁⠒⠠⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠃⠀⠀⢀⠎⠀⡰⠒⠁⠀⠀⠀⢠⠂⠀⠑⠐⠒⠀⠐⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠎⠑⢲⡀⠀⠀⠀⠀⠀⣠⠤⡀⠀⠀⠀⠀⠀⣀⣈⠡⠈⠦⣤⡀⠡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣖⠯⠐⠀⠀⠀⠀⢠⠃⠀⠀⠀⠀⠀⠘⠆⠀⠀⠀⠀⠀⠀⠈⠃⠀⢀⡠⠐⠂⠘⠀⢀⠎⠀⠀⠀⠀⠉⠅⠐⠢⡀⠀⠀⠈⠂⠒⠂⠠⠤⡀⠀⠓⡄⠀⠀⣘⡂⣣⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡔⡏⠄⠀⠀⠀⠀⠀⢀⣂⠁⠀⠀⠀⠀⠀⢀⡀⠘⠂⠀⠐⠒⠢⢀⠀⠀⠈⠉⡤⢀⡀⠀⠀⠋⠀⠀⣀⣀⠀⠀⠀⠀⠀⠈⠒⠀⠀⠀⠀⠀⠀⠀⠈⠂⠴⠀⠀⠀⠀⠀⠀⠡⠑⠦⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⡡⠐⢄⠢⠤⡤⠒⠪⠉⠐⢄⠀⠀⢀⡠⡎⡑⠠⠀⡠⠂⠀⠠⢈⣦⡄⡀⠀⢱⠈⠁⠂⠀⠀⠤⠔⡉⠉⠂⠀⠀⠀⢀⠀⠀⠀⡀⠤⠠⠤⢀⠀⠀⠀⠀⠀⢀⣀⠠⡤⡴⡖⠒⠂⣹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠛⠳⠶⠥⠖⢬⢲⣦⠵⢤⡨⢆⣈⣁⣀⢡⡐⣄⢣⡐⡄⠀⢢⡀⠸⢿⣴⣕⣂⡀⠀⡇⠀⠀⠀⠀⣇⠤⢒⣓⣀⡤⠄⡷⠶⢡⡤⣤⡶⡶⢬⡿⢿⠭⢝⣿⣛⣷⣾⣿⡕⢴⠥⠒⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠺⠦⢤⣌⢒⠠⠄⡘⣭⣍⠻⣛⣳⣾⣅⣀⡈⠽⣧⣼⠢⣙⣿⣮⠂⢄⡀⠀⢠⣷⣜⠫⣟⣗⠠⡾⠊⣀⣠⠿⠴⠿⡻⠉⣰⣥⣔⣥⠶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠐⠺⢍⣛⣛⣟⣿⣿⣿⣦⠹⠷⢶⡈⡛⠺⣾⡿⣿⠒⣛⣿⠭⣿⡿⢻⣏⣠⡾⠟⡳⠏⠕⢉⣰⣮⣴⠞⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠷⢤⢹⢳⢳⢿⡝⡟⠥⠜⡟⢡⣾⡻⣶⢿⣯⠶⠿⠛⠛⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠹⣟⠂⡎⣯⠸⣸⢱⣇⢬⣼⣷⡏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣷⠉⠃⡇⢾⡈⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢏⡌⣰⣿⣿⠧⡸⣎⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣸⣿⣏⣼⣿⣠⡙⡟⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠏⡾⢹⢿⣇⢋⣾⢱⣜⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣯⡟⣽⡿⣜⢮⣉⠚⡁⣨⣯⣿⡻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⠏⣱⠟⣴⣯⣄⣩⣙⣻⣬⣘⣌⠿⡿⢷⢤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢀⢤⠀⠀⢀⣼⣫⣵⣯⣇⣰⣯⣾⣿⣿⣴⣴⣛⣾⣿⣬⣛⡛⠾⡳⢷⣍⣛⠶⣤⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣰⣶⣷⠶⢿⡿⠾⠟⣫⠿⣟⣩⠿⡽⠛⢹⣿⣿⣿⣿⡜⠺⢀⠝⢻⣄⠻⢿⣷⠿⣿⣯⣙⡟⣾⣿⣿⡟⠛⠿⡿⠿⠟⠛⠶⡛⣳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣔⣻⡿⣿⣿⣿⣿⣷⣾⣚⣀⣤⠾⢿⡞⢋⠼⠞⢀⣴⣿⢿⣿⣿⣆⡣⠙⠬⠒⢬⣜⣧⣢⣙⣷⢿⣿⣿⣿⡿⠿⠿⣿⢿⣯⣭⣁⣶⣖⣒⣺⣖⠛⠛⢾⣿⣶⣶⣶⣶⣶⣶⣶⣶⣦⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀
⠠⠤⠤⠴⠶⣶⠶⣾⣶⣶⣶⣶⣶⡾⠿⢿⣿⣿⣿⣿⣯⣤⣾⠿⠿⣿⣿⣷⣿⣷⣾⣷⡶⠾⣛⣻⣿⣿⣿⣿⣶⣿⣭⣿⣿⣶⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣟⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠷⠤⠬⠭⠥⠤⠤⠤⠄
⠀⠀⠀⠀⠐⠛⠒⠉⠩⠽⣿⣿⣯⣥⣤⣬⣿⣿⣿⣿⣙⡛⠋⠀⠀⠉⠉⠉⠍⠩⠉⠩⠥⠤⠩⠭⠩⠯⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠩⣉⣉⣉⣉⣉⣉⣉⡉⠉⠉⠉⠉⠩⠭⠭⠉⠛⠋⠋⠛⠙⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠁⠈⠁⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`
        + `\x1b[0m`
    )
}