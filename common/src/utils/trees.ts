import { poseidon9, poseidon3, poseidon2, poseidon6, poseidon13 } from 'poseidon-lite';
import { ChildNodes, SMT } from '@openpassport/zk-kit-smt';
import { stringToAsciiBigIntArray } from './circuits/uuid';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';


export function formatRoot(root: string): string {
  let rootHex = BigInt(root).toString(16);
  return rootHex.length % 2 === 0 ? '0x' + rootHex : '0x0' + rootHex;
}

export function generateSMTProof(smt: SMT, leaf: bigint) {
  const { entry, matchingEntry, siblings, root, membership } = smt.createProof(leaf);
  const depth = siblings.length;

  let closestleaf;
  if (!matchingEntry) {
    // we got the 0 leaf or membership
    // then check if entry[1] exists
    if (!entry[1]) {
      // non membership proof
      closestleaf = BigInt(0); // 0 leaf
    } else {
      closestleaf = BigInt(entry[0]); // leaf itself (memb proof)
    }
  } else {
    // non membership proof
    closestleaf = BigInt(matchingEntry[0]); // actual closest
  }

  // PATH, SIBLINGS manipulation as per binary tree in the circuit
  siblings.reverse();
  while (siblings.length < 256) siblings.push(BigInt(0));

  // ----- Useful for debugging hence leaving as comments -----
  // const binary = entry[0].toString(2)
  // const bits = binary.slice(-depth);
  // let indices = bits.padEnd(256, "0").split("").map(Number)
  // const pathToMatch = num2Bits(256,BigInt(entry[0]))
  // while(indices.length < 256) indices.push(0);
  // // CALCULATED ROOT FOR TESTING
  // // closestleaf, depth, siblings, indices, root : needed
  // let calculatedNode = poseidon3([closestleaf,1,1]);
  // console.log("Initial node while calculating",calculatedNode)
  // console.log(smt.verifyProof(smt.createProof(leaf)))
  // for (let i= 0; i < depth ; i++) {
  //   const childNodes: any = indices[i] ? [siblings[i], calculatedNode] : [calculatedNode, siblings[i]]
  //   console.log(indices[i],childNodes)
  //   calculatedNode = poseidon2(childNodes)
  // }
  // console.log("Actual node", root)
  // console.log("calculated node", calculatedNode)
  // -----------------------------------------------------------

  return {
    root,
    depth,
    closestleaf,
    siblings,
  };
}

export function generateMerkleProof(imt: LeanIMT, _index: number, maxDepth: number) {
  const { siblings: merkleProofSiblings, index } = imt.generateProof(_index);
  const depthForThisOne = merkleProofSiblings.length;
  // The index must be converted to a list of indices, 1 for each tree level.
  // The circuit tree depth is 20, so the number of siblings must be 20, even if
  // the tree depth is actually 3. The missing siblings can be set to 0, as they
  // won't be used to calculate the root in the circuit.
  const merkleProofIndices: number[] = [];

  for (let i = 0; i < maxDepth; i += 1) {
    merkleProofIndices.push((index >> i) & 1);
    if (merkleProofSiblings[i] === undefined) {
      merkleProofSiblings[i] = BigInt(0);
    }
  }
  return { merkleProofSiblings, merkleProofIndices, depthForThisOne };
}




// SMT trees for 3 levels :
// 1. Passport tree  : level 3 (Absolute Match)
// 2. Names and dob combo tree : level 2 (High Probability Match)
// 3. Names tree : level 1 (Partial Match)
export function buildSMT(field: any[], treetype: string): [number, number, SMT] {
  let count = 0;
  let startTime = performance.now();

  const hash2 = (childNodes: ChildNodes) =>
    childNodes.length === 2 ? poseidon2(childNodes) : poseidon3(childNodes);
  const tree = new SMT(hash2, true);

  for (let i = 0; i < field.length; i++) {
    const entry = field[i];

    if (i !== 0) {
      console.log('Processing', treetype, 'number', i, 'out of', field.length);
    }

    let leaf = BigInt(0);
    if (treetype == 'passport') {
      leaf = processPassport(entry.Pass_No, i);
    } else if (treetype == 'name_dob') {
      leaf = processNameDob(entry, i);
    } else if (treetype == 'name') {
      leaf = processName(entry.First_Name, entry.Last_Name, i);
    } else if (treetype == 'country') {
      const keys = Object.keys(entry);
      leaf = processCountry(keys[0], entry[keys[0]], i);
    }

    if (leaf == BigInt(0) || tree.createProof(leaf).membership) {
      console.log('This entry already exists in the tree, skipping...');
      continue;
    }

    count += 1;
    tree.add(leaf, BigInt(1));
  }

  console.log('Total', treetype, 'paresed are : ', count, ' over ', field.length);
  console.log(treetype, 'tree built in', performance.now() - startTime, 'ms');
  return [count, performance.now() - startTime, tree];
}

function processPassport(passno: string, index: number): bigint {
  if (passno.length > 9) {
    console.log('passport length is greater than 9:', index, passno);
  } else if (passno.length < 9) {
    while (passno.length != 9) {
      passno += '<';
    }
  }

  const leaf = getPassportNumberLeaf(stringToAsciiBigIntArray(passno));
  if (!leaf) {
    console.log('Error creating leaf value', index, passno);
    return BigInt(0);
  }
  return leaf;
}

function processNameDob(entry: any, i: number): bigint {
  const firstName = entry.First_Name;
  const lastName = entry.Last_Name;
  const day = entry.day;
  const month = entry.month;
  const year = entry.year;
  if (day == null || month == null || year == null) {
    console.log('dob is null', i, entry);
    return BigInt(0);
  }
  const nameHash = processName(firstName, lastName, i);
  const dobHash = processDob(day, month, year, i);
  const leaf = poseidon2([dobHash, nameHash]);
  return leaf;
}

function processName(firstName: string, lastName: string, i: number): bigint {
  // LASTNAME<<FIRSTNAME<MIDDLENAME<<<... (6-44)
  firstName = firstName.replace(/'/g, '');
  firstName = firstName.replace(/\./g, '');
  firstName = firstName.replace(/[- ]/g, '<');
  lastName = lastName.replace(/'/g, '');
  lastName = lastName.replace(/[- ]/g, '<');
  lastName = lastName.replace(/\./g, '');
  // Removed apostrophes from the first name, eg O'Neil -> ONeil
  // Replace spaces and hyphens with '<' in the first name, eg John Doe -> John<Doe
  // TODO : Handle special cases like malaysia : no two filler characters like << for surname and givenname
  // TODO : Verify rules for . in names. eg : J. Doe (Done same as apostrophe for now)

  let arr = lastName + '<<' + firstName;
  if (arr.length > 39) {
    arr = arr.substring(0, 39);
  } else {
    while (arr.length < 39) {
      arr += '<';
    }
  }
  let nameArr = stringToAsciiBigIntArray(arr);
  return getNameLeaf(nameArr, i);
}

function processDob(day: string, month: string, year: string, i: number): bigint {
  // YYMMDD
  const monthMap: { [key: string]: string } = {
    jan: '01',
    feb: '02',
    mar: '03',
    apr: '04',
    may: '05',
    jun: '06',
    jul: '07',
    aug: '08',
    sep: '09',
    oct: '10',
    nov: '11',
    dec: '12',
  };

  month = monthMap[month.toLowerCase()];
  year = year.slice(-2);
  const dob = year + month + day;
  let arr = stringToAsciiBigIntArray(dob);
  return getDobLeaf(arr, i);
}

function processCountry(country1: string, country2: string, i: number) {
  let arr = stringToAsciiBigIntArray(country1);
  let arr2 = stringToAsciiBigIntArray(country2);

  const leaf = getCountryLeaf(arr, arr2, i);
  if (!leaf) {
    console.log('Error creating leaf value', i, country1, country2);
    return BigInt(0);
  }
  return leaf;
}

export function getCountryLeaf(
  country_by: (bigint | number)[],
  country_to: (bigint | number)[],
  i?: number
): bigint {
  if (country_by.length !== 3 || country_to.length !== 3) {
    console.log('parsed passport length is not 3:', i, country_to, country_by);
    return;
  }
  try {
    const country = country_by.concat(country_to);
    return poseidon6(country);
  } catch (err) {
    console.log('err : sanc_country hash', err, i, country_by, country_to);
  }
}

export function getPassportNumberLeaf(passport: (bigint | number)[], i?: number): bigint {
  if (passport.length !== 9) {
    console.log('parsed passport length is not 9:', i, passport);
    return;
  }
  try {
    return poseidon9(passport);
  } catch (err) {
    console.log('err : passport', err, i, passport);
  }
}

export function getNameDobLeaf(
  nameMrz: (bigint | number)[],
  dobMrz: (bigint | number)[],
  i?: number
): bigint {
  return poseidon2([getDobLeaf(dobMrz), getNameLeaf(nameMrz)]);
}

export function getNameLeaf(nameMrz: (bigint | number)[], i?: number): bigint {
  let middleChunks: bigint[] = [];
  let chunks: (number | bigint)[][] = [];

  chunks.push(nameMrz.slice(0, 13), nameMrz.slice(13, 26), nameMrz.slice(26, 39)); // 39/3 for posedion to digest

  for (const chunk of chunks) {
    middleChunks.push(poseidon13(chunk));
  }

  try {
    return poseidon3(middleChunks);
  } catch (err) {
    console.log('err : Name', err, i, nameMrz);
  }
}

export function getDobLeaf(dobMrz: (bigint | number)[], i?: number): bigint {
  if (dobMrz.length !== 6) {
    console.log('parsed dob length is not 9:', i, dobMrz);
    return;
  }
  try {
    return poseidon6(dobMrz);
  } catch (err) {
    console.log('err : Dob', err, i, dobMrz);
  }
}
