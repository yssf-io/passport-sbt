import { assert } from "chai";
import { ethers } from "hardhat";
import { mockPassportData_sha256WithRSAEncryption_65537 } from "../../common/src/utils/mockPassportData";
import { groth16 } from 'snarkjs'
import { revealBitmapFromMapping } from "../../common/src/utils/revealBitmap";
import { generateCircuitInputs } from "../../common/src/utils/generateInputs";
import fs from 'fs';

async function main() {
  const proofOfPassportAddress = "0xF3F619aB057E3978204Be68549f9D4a503EAa535"
  const proofOfPassport = await ethers.getContractAt("OpenPassport", proofOfPassportAddress);

  const passportData = mockPassportData_sha256WithRSAEncryption_65537;

  const attributeToReveal = {
    issuing_state: true,
    name: true,
    passport_number: true,
    nationality: true,
    date_of_birth: true,
    gender: true,
    expiry_date: true,
    older_than: true,
  }

  const reveal_bitmap = revealBitmapFromMapping(attributeToReveal)

  const address = "0xE6E4b6a802F2e0aeE5676f6010e0AF5C9CDd0a50";

  const inputs = generateCircuitInputs(
    passportData,
    reveal_bitmap,
    address,
    18,
  );

  console.log('generating proof...');
  const { proof, publicSignals } = await groth16.fullProve(
    inputs,
    "../circuits/build/proof_of_passport_js/proof_of_passport.wasm",
    "../circuits/build/proof_of_passport_final.zkey"
  )

  console.log('proof done');

  const vKey = JSON.parse(fs.readFileSync("../circuits/build/proof_of_passport_vkey.json") as unknown as string);

  const verified = await groth16.verify(
    vKey,
    publicSignals,
    proof
  )

  assert(verified == true, 'Should verifiable')

  const cd = await groth16.exportSolidityCallData(proof, publicSignals);
  const callData = JSON.parse(`[${cd}]`);
  console.log('callData', callData);

  const tx = await proofOfPassport.mint(...callData);

  const receipt = await tx.wait();
  console.log('receipt', receipt?.hash);
  const tokenURI = await proofOfPassport.tokenURI(0);
  console.log('tokenURI', tokenURI);
}


main().catch((error) => {
  console.error("Error in main:", error);
  process.exit(1);
});
