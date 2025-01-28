import * as fs from 'fs';
import { getLeafDscTreeFromParsedDsc } from '../../../common/src/utils/pubkeyTree';
import { CSCA_TREE_DEPTH, DEVELOPMENT_MODE } from '../../../common/src/constants/constants';
import { IMT } from '@openpassport/zk-kit-imt';
import { poseidon2 } from 'poseidon-lite';
import { writeFile } from 'fs/promises';
import * as path from 'path';
import { parseCertificate } from '../../../common/src/utils/certificate_parsing/parseCertificate';

let tbs_max_bytes = 0;
let key_length_max_bytes = 0;

function processCertificate(pemContent: string, filePath: string) {
    try {
        const certificate = parseCertificate(pemContent, path.basename(filePath));
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
            console.log(`Skipping file ${filePath}: Key length ${keyLength} bits exceeds 4096 bits`);
            return null;
        }

        console.log(`File: ${filePath}`);
        console.log(`Key Length: ${keyLength} bits`);
        console.log(`Signature Algorithm: ${certificate.signatureAlgorithm}`);
        console.log(`Hash Algorithm: ${certificate.hashAlgorithm}`);

        const finalPoseidonHash = getLeafDscTreeFromParsedDsc(certificate);
        console.log(`Final Poseidon Hash: ${finalPoseidonHash}`);

        return finalPoseidonHash.toString();
    } catch (error) {
        console.error(`Error processing certificate ${filePath}:`, error);
        return null;
    }
}

async function buildCscaMerkleTree() {
    const tree = new IMT(poseidon2, CSCA_TREE_DEPTH, 0, 2);

    const path_to_pem_files = "outputs/dsc/pem_masterlist";
    for (const file of fs.readdirSync(path_to_pem_files)) {
        const file_path = path.join(path_to_pem_files, file);
        try {
            const pemContent = fs.readFileSync(file_path, 'utf8');
            const leafValue = processCertificate(pemContent, file_path);
            if (leafValue) {
                tree.insert(leafValue);
            }
        } catch (error) {
            console.error(`Error reading file ${file}:`, error);
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
                        tree.insert(leafValue);
                    }
                } catch (error) {
                    console.error(`Error processing mock file ${pemFilePath}:`, error);
                }
            }
        }
    }

    console.log(`Max TBS bytes: ${tbs_max_bytes}`);
    console.log(`Max Key Length: ${key_length_max_bytes}`);
    return tree;
}

async function serializeCscaTree(tree: IMT) {
    const serializedTree = tree.nodes.map(layer => layer.map(node => node.toString()));
    await writeFile("outputs/serialized_dsc_tree.json", JSON.stringify(serializedTree));
    fs.copyFileSync("outputs/serialized_dsc_tree.json", "../common/pubkeys/serialized_dsc_tree.json");
    console.log("serialized_dsc_tree.json written and copied in common/pubkeys!");
}

async function main() {
    const tree = await buildCscaMerkleTree();
    await serializeCscaTree(tree);
}

main();