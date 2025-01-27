// // SPDX-License-Identifier: GPL-3.0
// /*
//     Copyright 2021 0KIMS association.

//     This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

//     snarkJS is a free software: you can redistribute it and/or modify it
//     under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     snarkJS is distributed in the hope that it will be useful, but WITHOUT
//     ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//     or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
//     License for more details.

//     You should have received a copy of the GNU General Public License
//     along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
// */

// pragma solidity >=0.7.0 <0.9.0;

// contract Verifier_dsc_rsa_sha1_65537_4096 {
//     // Scalar field size
//     uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
//     // Base field size
//     uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

//     // Verification Key data
//     uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
//     uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
//     uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
//     uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
//     uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
//     uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
//     uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
//     uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
//     uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
//     uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
//     uint256 constant deltax1 = 9007101952074238519015752701836652177051167766617240799749420929121212290574;
//     uint256 constant deltax2 = 14480478890866522259226736728373156323983364937114952786638874306209309618749;
//     uint256 constant deltay1 = 4111906931737628235316931735795173203992721154159197299982698278307336216279;
//     uint256 constant deltay2 = 20555285485333959366117469630105495479207833841239299266749732011871692062045;

    
//     uint256 constant IC0x = 17267442441183019371828573930937951883926148550454878375898203984237211725187;
//     uint256 constant IC0y = 9711625273509505655288805089383556996803345972030345774641793380857248833459;
    
//     uint256 constant IC1x = 4696321433753699665236307797222541337537360929629981577179833953323923184646;
//     uint256 constant IC1y = 9176410504028005643882490229389082569751844946548783462517124849274326604548;
    
//     uint256 constant IC2x = 12667795222628237459376685073717945025783991597106184736638781490147549000456;
//     uint256 constant IC2y = 14878225299311863759687142187944761177517628539681796253479927185229117349038;
    
 
//     // Memory data
//     uint16 constant pVk = 0;
//     uint16 constant pPairing = 128;

//     uint16 constant pLastMem = 896;

//     function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[2] calldata _pubSignals) public view returns (bool) {
//         assembly {
//             function checkField(v) {
//                 if iszero(lt(v, r)) {
//                     mstore(0, 0)
//                     return(0, 0x20)
//                 }
//             }
            
//             // G1 function to multiply a G1 value(x,y) to value in an address
//             function g1_mulAccC(pR, x, y, s) {
//                 let success
//                 let mIn := mload(0x40)
//                 mstore(mIn, x)
//                 mstore(add(mIn, 32), y)
//                 mstore(add(mIn, 64), s)

//                 success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

//                 if iszero(success) {
//                     mstore(0, 0)
//                     return(0, 0x20)
//                 }

//                 mstore(add(mIn, 64), mload(pR))
//                 mstore(add(mIn, 96), mload(add(pR, 32)))

//                 success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

//                 if iszero(success) {
//                     mstore(0, 0)
//                     return(0, 0x20)
//                 }
//             }

//             function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
//                 let _pPairing := add(pMem, pPairing)
//                 let _pVk := add(pMem, pVk)

//                 mstore(_pVk, IC0x)
//                 mstore(add(_pVk, 32), IC0y)

//                 // Compute the linear combination vk_x
                
//                 g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
//                 g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                

//                 // -A
//                 mstore(_pPairing, calldataload(pA))
//                 mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

//                 // B
//                 mstore(add(_pPairing, 64), calldataload(pB))
//                 mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
//                 mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
//                 mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

//                 // alpha1
//                 mstore(add(_pPairing, 192), alphax)
//                 mstore(add(_pPairing, 224), alphay)

//                 // beta2
//                 mstore(add(_pPairing, 256), betax1)
//                 mstore(add(_pPairing, 288), betax2)
//                 mstore(add(_pPairing, 320), betay1)
//                 mstore(add(_pPairing, 352), betay2)

//                 // vk_x
//                 mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
//                 mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


//                 // gamma2
//                 mstore(add(_pPairing, 448), gammax1)
//                 mstore(add(_pPairing, 480), gammax2)
//                 mstore(add(_pPairing, 512), gammay1)
//                 mstore(add(_pPairing, 544), gammay2)

//                 // C
//                 mstore(add(_pPairing, 576), calldataload(pC))
//                 mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

//                 // delta2
//                 mstore(add(_pPairing, 640), deltax1)
//                 mstore(add(_pPairing, 672), deltax2)
//                 mstore(add(_pPairing, 704), deltay1)
//                 mstore(add(_pPairing, 736), deltay2)


//                 let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

//                 isOk := and(success, mload(_pPairing))
//             }

//             let pMem := mload(0x40)
//             mstore(0x40, add(pMem, pLastMem))

//             // Validate that all evaluations ∈ F
            
//             checkField(calldataload(add(_pubSignals, 0)))
            
//             checkField(calldataload(add(_pubSignals, 32)))
            

//             // Validate all evaluations
//             let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

//             mstore(0, isValid)
//              return(0, 0x20)
//          }
//      }
//  }
