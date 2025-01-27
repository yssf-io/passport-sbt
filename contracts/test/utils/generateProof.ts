const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';

import type { 
    PublicSignals,
    Groth16Proof,
    CircuitSignals,
} from "snarkjs";
import { groth16 } from "snarkjs";
import fs from "fs";
import { SMT, ChildNodes } from "@openpassport/zk-kit-smt";
import { poseidon2, poseidon3 } from "poseidon-lite";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import path from "path";
import { RegisterCircuitProof, DscCircuitProof, CircuitArtifacts, VcAndDiscloseProof } from "./types";
import { PassportData } from "../../../common/src/utils/types";
import { buildSMT } from "../../../common/src/utils/trees";

import {BigNumberish} from "ethers";
import { 
    generateCircuitInputsRegister,
    generateCircuitInputsVCandDisclose
} from "../../../common/src/utils/circuits/generateInputs";
import { generateCircuitInputsDSC } from "../../../common/src/utils/csca";

const registerCircuits: CircuitArtifacts = {
    "register_sha256_sha256_sha256_rsa_65537_4096": {
        wasm: "../circuits/build/register/register_sha256_sha256_sha256_rsa_65537_4096/register_sha256_sha256_sha256_rsa_65537_4096_js/register_sha256_sha256_sha256_rsa_65537_4096.wasm",
        zkey: "../circuits/build/register/register_sha256_sha256_sha256_rsa_65537_4096/register_sha256_sha256_sha256_rsa_65537_4096_final.zkey",
        vkey: "../circuits/build/register/register_sha256_sha256_sha256_rsa_65537_4096/register_sha256_sha256_sha256_rsa_65537_4096_vkey.json"
    }
};
const dscCircuits: CircuitArtifacts = {
    "dsc_sha256_sha256_sha256_rsa_65537_4096": {
        wasm: "../circuits/build/dsc/dsc_rsa_sha256_65537_4096/dsc_rsa_sha256_65537_4096_js/dsc_rsa_sha256_65537_4096.wasm",
        zkey: "../circuits/build/dsc/dsc_rsa_sha256_65537_4096/dsc_rsa_sha256_65537_4096_final.zkey",
        vkey: "../circuits/build/dsc/dsc_rsa_sha256_65537_4096/dsc_rsa_sha256_65537_4096_vkey.json"
    }
};
const vcAndDiscloseCircuits: CircuitArtifacts = {
    "vc_and_disclose": {
        wasm: "../circuits/build/disclose/vc_and_disclose/vc_and_disclose_js/vc_and_disclose.wasm",
        zkey: "../circuits/build/disclose/vc_and_disclose/vc_and_disclose_final.zkey",
        vkey: "../circuits/build/disclose/vc_and_disclose/vc_and_disclose_vkey.json"
    }
}

export async function generateRegisterProof(
    secret: number | string,
    dscSecret: number | string,
    passportData: PassportData
): Promise<RegisterCircuitProof> {
    console.log(CYAN, "=== Start generateRegisterProof ===", RESET);
    
    // Get the circuit inputs
    const registerCircuitInputs: CircuitSignals = generateCircuitInputsRegister(
        secret,
        dscSecret,
        passportData
    );

    // Generate the proof
    const startTime = performance.now();
    
    const registerProof: {
        proof: Groth16Proof,
        publicSignals: PublicSignals
    } = await groth16.fullProve(
        registerCircuitInputs,
        registerCircuits["register_sha256_sha256_sha256_rsa_65537_4096"].wasm,
        registerCircuits["register_sha256_sha256_sha256_rsa_65537_4096"].zkey
    );
    
    const endTime = performance.now();
    console.log(GREEN, `groth16.fullProve execution time: ${((endTime - startTime) / 1000).toFixed(2)} seconds`, RESET);

    // Verify the proof
    const vKey = JSON.parse(fs.readFileSync(registerCircuits["register_sha256_sha256_sha256_rsa_65537_4096"].vkey, 'utf8'));
    const isValid = await groth16.verify(vKey, registerProof.publicSignals, registerProof.proof);
    if (!isValid) {
        throw new Error("Generated register proof verification failed");
    }
    console.log(GREEN, "Register proof verified successfully", RESET);

    const rawCallData = await groth16.exportSolidityCallData(registerProof.proof, registerProof.publicSignals);
    const fixedProof = parseSolidityCalldata(rawCallData, {} as RegisterCircuitProof);

    console.log(CYAN, "=== End generateRegisterProof ===", RESET);
    return fixedProof;
}

export async function generateDscProof(
    dscSecret: string,
    dscCertificate: any,
    maxCertBytes: number,
): Promise<DscCircuitProof> {
    console.log(CYAN, "=== Start generateDscProof ===", RESET);

    const dscCircuitInputs: CircuitSignals = generateCircuitInputsDSC(
        dscSecret,
        dscCertificate,
        maxCertBytes,
        true
    ).inputs;

    const startTime = performance.now();
    const dscProof = await groth16.fullProve(
        dscCircuitInputs,
        dscCircuits["dsc_sha256_sha256_sha256_rsa_65537_4096"].wasm,
        dscCircuits["dsc_sha256_sha256_sha256_rsa_65537_4096"].zkey
    );
    const endTime = performance.now();
    console.log(GREEN, `groth16.fullProve execution time: ${((endTime - startTime) / 1000).toFixed(2)} seconds`, RESET);

    // Verify the proof
    const vKey = JSON.parse(fs.readFileSync(dscCircuits["dsc_sha256_sha256_sha256_rsa_65537_4096"].vkey, 'utf8'));
    const isValid = await groth16.verify(vKey, dscProof.publicSignals, dscProof.proof);
    if (!isValid) {
        throw new Error("Generated DSC proof verification failed");
    }
    console.log(GREEN, "DSC proof verified successfully", RESET);

    const rawCallData = await groth16.exportSolidityCallData(dscProof.proof, dscProof.publicSignals);
    const fixedProof = parseSolidityCalldata(rawCallData, {} as DscCircuitProof);

    console.log(CYAN, "=== End generateDscProof ===", RESET);
    return fixedProof;
}

export async function generateVcAndDiscloseProof(
    secret: string,
    attestationId: string,
    passportData: PassportData,
    scope: string,
    selectorDg1: string[] = new Array(93).fill("1"),
    selectorOlderThan: string | number = "1",
    merkletree: LeanIMT<bigint>,
    majority: string = "20",
    smt?: SMT,
    selectorOfac: string | number = "1",
    forbiddenCountriesList: string[] = ["AAA"],
    userIdentifier: string = "70997970C51812dc3A010C7d01b50e0d17dc79C8"
): Promise<VcAndDiscloseProof> {

    smt = getSMT();
    
    const vcAndDiscloseCircuitInputs: CircuitSignals = generateCircuitInputsVCandDisclose(
        secret,
        attestationId,
        passportData,
        scope,
        selectorDg1,
        selectorOlderThan,
        merkletree,
        majority,
        smt,
        selectorOfac,
        forbiddenCountriesList,
        userIdentifier
    );

    const startTime = performance.now();
    const vcAndDiscloseProof = await groth16.fullProve(
        vcAndDiscloseCircuitInputs,
        vcAndDiscloseCircuits["vc_and_disclose"].wasm,
        vcAndDiscloseCircuits["vc_and_disclose"].zkey
    );
    const endTime = performance.now();
    console.log(GREEN, `groth16.fullProve execution time: ${((endTime - startTime) / 1000).toFixed(2)} seconds`, RESET);

    // Verify the proof
    const vKey = JSON.parse(fs.readFileSync(vcAndDiscloseCircuits["vc_and_disclose"].vkey, 'utf8'));
    const isValid = await groth16.verify(vKey, vcAndDiscloseProof.publicSignals, vcAndDiscloseProof.proof);
    if (!isValid) {
        throw new Error("Generated VC and Disclose proof verification failed");
    }
    console.log(GREEN, "VC and Disclose proof verified successfully", RESET);

    const rawCallData = await groth16.exportSolidityCallData(vcAndDiscloseProof.proof, vcAndDiscloseProof.publicSignals);
    const fixedProof = parseSolidityCalldata(rawCallData, {} as VcAndDiscloseProof);

    console.log(CYAN, "=== End generateVcAndDiscloseProof ===", RESET);
    return fixedProof;
}

function parseSolidityCalldata<T>(rawCallData: string, _type: T): T {
    const parsed = JSON.parse("[" + rawCallData + "]");
    
    return {
        a: parsed[0].map((x: string) => x.replace(/"/g, '')) as [BigNumberish, BigNumberish],
        b: parsed[1].map((arr: string[]) => 
            arr.map((x: string) => x.replace(/"/g, ''))
        ) as [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
        c: parsed[2].map((x: string) => x.replace(/"/g, '')) as [BigNumberish, BigNumberish],
        pubSignals: parsed[3].map((x: string) => x.replace(/"/g, '')) as BigNumberish[]
    } as T;
}

export function getSMT() {
    let name = fs.readFileSync("../common/ofacdata/inputs/names.json", "utf-8");
    let name_list = JSON.parse(name);
    let mockSmt;
    if (fs.existsSync("./test/utils/smt.json")) {
        mockSmt = importSMTFromJsonFile("./test/utils/smt.json") as SMT;
    } else {
        const builtSmt = buildSMT(name_list, "name");
        exportSMTToJsonFile(builtSmt[0], builtSmt[1], builtSmt[2], "./test/utils/smt.json");
        mockSmt = builtSmt[2] as SMT;
    }
    return mockSmt;
}

function exportSMTToJsonFile(count: number, time: number, smt: SMT, outputPath?: string) {
    const serializedSMT = smt.export();
    const data = {
        count: count,
        time: time,
        smt: serializedSMT
    };
    const jsonString = JSON.stringify(data, null, 2);
    const defaultPath = path.join(process.cwd(), 'smt.json');
    const finalPath = outputPath ? path.resolve(process.cwd(), outputPath) : defaultPath;
  
    fs.writeFileSync(finalPath, jsonString, 'utf8');
}

function importSMTFromJsonFile(filePath?: string): SMT | null {
    try {
        const jsonString = fs.readFileSync(path.resolve(process.cwd(), filePath as string), 'utf8');
          
        const data = JSON.parse(jsonString);
          
        const hash2 = (childNodes: ChildNodes) => (childNodes.length === 2 ? poseidon2(childNodes) : poseidon3(childNodes));
        const smt = new SMT(hash2, true);
        smt.import(data.smt);
          
        console.log('Successfully imported SMT from JSON file');
        return smt;
    } catch (error) {
        console.error('Failed to import SMT from JSON file:', error);
        return null;
    }
}