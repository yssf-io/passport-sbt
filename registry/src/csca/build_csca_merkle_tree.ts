import * as fs from 'fs';
import { getLeafCSCA } from '../../../common/src/utils/pubkeyTree';
import { CSCA_TREE_DEPTH, DEVELOPMENT_MODE } from '../../../common/src/constants/constants';
import { IMT } from '@openpassport/zk-kit-imt';
import { poseidon2 } from 'poseidon-lite';
import { writeFile } from 'fs/promises';
import * as path from 'path';
import { parseCertificate } from '../../../common/src/utils/certificate_parsing/parseCertificate';

function processCertificate(pemContent: string, filePath: string) {
    try {
        const certificate = parseCertificate(pemContent, path.basename(filePath));

        const validAlgorithms = ['rsa', 'rsapss'];
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

        const finalPoseidonHash = getLeafCSCA(pemContent);
        console.log(`Final Poseidon Hash: ${finalPoseidonHash}`);

        return finalPoseidonHash.toString();
    } catch (error) {
        console.error(`Error processing certificate ${filePath}:`, error);
        return null;
    }
}

async function buildCscaMerkleTree() {
    const tree = new IMT(poseidon2, CSCA_TREE_DEPTH, 0, 2);

    const path_to_pem_files = "outputs/csca/pem_masterlist";
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
        const mockCscaList = [
            '../common/src/mock_certificates/sha256_rsa_4096/mock_csca.pem',
            '../common/src/mock_certificates/sha256_rsapss_4096/mock_csca.pem',
            '../common/src/mock_certificates/sha1_rsa_4096/mock_csca.crt',
            '../common/src/mock_certificates/sha1_rsa_3_4096/mock_csca.pem',
            '../common/src/mock_certificates/sha256_rsa_3_4096/mock_csca.crt',
            '../common/src/mock_certificates/sha384_rsa_65537_4096/mock_csca.pem',
            '../common/src/mock_certificates/sha512_rsa_65537_4096/mock_csca.pem',
        ];

        for (const mockCscaFile of mockCscaList) {
            try {
                const pemContent = fs.readFileSync(mockCscaFile, 'utf8');
                const leafValue = processCertificate(pemContent, mockCscaFile);
                if (leafValue) {
                    tree.insert(leafValue);
                }
            } catch (error) {
                console.error(`Error processing mock file ${mockCscaFile}:`, error);
            }
        }
    }

    return tree;
}

async function serializeCscaTree(tree: IMT) {
    const serializedTree = tree.nodes.map(layer => layer.map(node => node.toString()));
    await writeFile("outputs/serialized_csca_tree.json", JSON.stringify(serializedTree));
    fs.copyFileSync("outputs/serialized_csca_tree.json", "../common/pubkeys/serialized_csca_tree.json");
    console.log("serialized_csca_tree.json written and copied in common/pubkeys!");
}

async function main() {
    const tree = await buildCscaMerkleTree();
    await serializeCscaTree(tree);
}

main();