import { randomBytes, toBigInt, toBeHex, zeroPadValue } from "ethers";

export function generateRandomFieldElement(): string {
  const FIELD_PRIME = BigInt(
    "21888242871839275222246405745257275088696311157297823662689037894645226208583"
  );
  
  const fieldElement = zeroPadValue(toBeHex(toBigInt(randomBytes(32)) % FIELD_PRIME), 32);
  
  return fieldElement;
}