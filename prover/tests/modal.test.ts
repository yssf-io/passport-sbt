import { generateCircuitInputsDSC, sendCSCARequest } from "../../common/src/utils/csca";
import { mock_csca_sha256_rsa_4096, mock_dsc_sha256_rsa_4096, mock_csca_sha1_rsa_4096, mock_dsc_sha1_rsa_4096, mock_csca_sha256_rsapss_4096, mock_dsc_sha256_rsapss_4096 } from "../../common/src/constants/mockCertificates";
import forge from "node-forge";
import { k_csca, k_dsc, MODAL_SERVER_ADDRESS, n_csca, n_dsc } from "../../common/src/constants/constants";
import axios from 'axios';
import fs from 'fs';
import { groth16 } from 'snarkjs'
import { expect } from "chai";
import path from 'path';

const max_dsc_bytes = 1664;

const vkey_sha256_rsa = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/vkey/dsc_rsa_65537_sha256_4096_vkey.json'), 'utf8'));
const vkey_sha256_rsapss = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/vkey/dsc_rsapss_65537_sha256_4096_vkey.json'), 'utf8'));
const vkey_sha1_rsa = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/vkey/dsc_rsa_65537_sha1_4096_vkey.json'), 'utf8'));

describe('MODAL PROVER', function () {
    this.timeout(0); // Disable timeout

    describe("SHA256 RSAPSS", async () => {
        it("verify proof", async () => {
            const inputs = generateCircuitInputsDSC(
                BigInt(0).toString(),
                mock_dsc_sha256_rsapss_4096,
                max_dsc_bytes,
                true
            );
            console.log('\x1b[34msending request to modal server\x1b[0m');
            const response = await sendCSCARequest(inputs);
            console.log('\x1b[34mresponse from modal server received\x1b[0m');
            const proof = JSON.parse(JSON.stringify(response));
            const verifyProof = await groth16.verify(
                vkey_sha256_rsapss,
                proof.pub_signals,
                proof.proof
            )
            expect(verifyProof).to.be.true;
            console.log('\x1b[32mproof for sha256 rsapss verified\x1b[0m');
        });
    });
    describe("SHA256 RSA", async () => {
        it("verify proof", async () => {
            const inputs = generateCircuitInputsDSC(
                BigInt(0).toString(),
                mock_dsc_sha256_rsa_4096,
                max_dsc_bytes,
                true
            );
            //console.log(JSON.stringify(inputs));
            console.log('\x1b[34msending request to modal server\x1b[0m');
            const response = await sendCSCARequest(inputs);
            console.log('\x1b[34mresponse from modal server received\x1b[0m');
            const proof = JSON.parse(JSON.stringify(response));
            const verifyProof = await groth16.verify(
                vkey_sha256_rsa,
                proof.pub_signals,
                proof.proof
            )
            expect(verifyProof).to.be.true;
            console.log('\x1b[32mproof for sha256 rsa verified\x1b[0m');
        });
    });

    describe("SHA1 RSA", async () => {
        it("verify proof", async () => {
            const inputs = generateCircuitInputsDSC(
                BigInt(0).toString(),
                mock_dsc_sha1_rsa_4096,
                max_dsc_bytes,
                true
            );

            console.log('\x1b[34msending request to modal server\x1b[0m');
            const response = await sendCSCARequest(inputs);
            console.log('\x1b[34mresponse from modal server received\x1b[0m');
            const proof = JSON.parse(JSON.stringify(response));
            const verifyProof = await groth16.verify(
                vkey_sha1_rsa,
                proof.pub_signals,
                proof.proof
            )
            expect(verifyProof).to.be.true;
            console.log('\x1b[32mproof for sha1 rsa verified\x1b[0m');

        });
    });
});
