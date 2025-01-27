export function formatCallData_register(parsedCallData: any[]) {
  return {
    blinded_dsc_commitment: parsedCallData[3][0],
    nullifier: parsedCallData[3][1],
    commitment: parsedCallData[3][2],
    attestation_id: parsedCallData[3][3],
    a: parsedCallData[0],
    b: [parsedCallData[1][0], parsedCallData[1][1]],
    c: parsedCallData[2],
  };
}
export function formatCallData_dsc(parsedCallData: any[]) {
  return {
    blinded_dsc_commitment: parsedCallData[3][0],
    merkle_root: parsedCallData[3][1],
    a: parsedCallData[0],
    b: [parsedCallData[1][0], parsedCallData[1][1]],
    c: parsedCallData[2],
  };
}

export function formatCallData_disclose(parsedCallData: any[]) {
  return {
    nullifier: parsedCallData[3][0],
    revealedData_packed: [parsedCallData[3][1], parsedCallData[3][2], parsedCallData[3][3]],
    attestation_id: parsedCallData[3][4],
    merkle_root: parsedCallData[3][5],
    scope: parsedCallData[3][6],
    current_date: [
      parsedCallData[3][7],
      parsedCallData[3][8],
      parsedCallData[3][9],
      parsedCallData[3][10],
      parsedCallData[3][11],
      parsedCallData[3][12],
    ],
    user_identifier: parsedCallData[3][13],
    a: parsedCallData[0],
    b: [parsedCallData[1][0], parsedCallData[1][1]],
    c: parsedCallData[2],
  };
}
