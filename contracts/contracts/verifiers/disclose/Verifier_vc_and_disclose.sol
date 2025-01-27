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

// contract Verifier_vc_and_disclose {
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
//     uint256 constant deltax1 = 2174239213634988219776773312960432398388455058553273695967516095612718948693;
//     uint256 constant deltax2 = 18216674290331595525675070282631771344996981530740480545918028090944281397637;
//     uint256 constant deltay1 = 6392666274815988672377039359470622699946555174530797215226827275316003779368;
//     uint256 constant deltay2 = 699304604506164684057553682477580041397527689288821968988746189325007608205;

    
//     uint256 constant IC0x = 3479000222179882457774124113903664110635971666282159847551916194874024588440;
//     uint256 constant IC0y = 7809862499320125196791345312591255739117868812776094655769266148458274064899;
    
//     uint256 constant IC1x = 15084771353119455364147534836094393027830785837434097568514028042839591971489;
//     uint256 constant IC1y = 7746984156298356603670564249832071482745315550903165027739814537520109757837;
    
//     uint256 constant IC2x = 21336312621158782186308836930932074845113443316249540575029759919956072117543;
//     uint256 constant IC2y = 10797005377643388076836226806827482901853968632987808418471336562466465687914;
    
//     uint256 constant IC3x = 3901763393980437365882592551309016529740499866320936821217231521098748619658;
//     uint256 constant IC3y = 19582041607984933380888154069045642898095103541392853376862232268388600008291;
    
//     uint256 constant IC4x = 4116096368656470933365751366043851245310542771685632790173573685028237732293;
//     uint256 constant IC4y = 12115198570787208655424268939678974858614903125982858214442816297160088305182;
    
//     uint256 constant IC5x = 10679052607030485341124497903265911846220928824959012106878064282122831841610;
//     uint256 constant IC5y = 16158835375615812370278422617526577893787723537848773619299814043857920715458;
    
//     uint256 constant IC6x = 3376566989791408937601610441051781262016523360739948494388968738042834801228;
//     uint256 constant IC6y = 15132330595401792338020073275418077164363750147544367779691333117625657210447;
    
//     uint256 constant IC7x = 14822573388243693488787619207910036116563206164178449640679283085355631333007;
//     uint256 constant IC7y = 17780810146307519345654204996736722089001456529350608545839731827866959562866;
    
//     uint256 constant IC8x = 13853772995693506765158162840235521638050653382414465519942377470893667195387;
//     uint256 constant IC8y = 14046943080268353052726787186318415856859369235377456677075618017795183798620;
    
//     uint256 constant IC9x = 12130538414604719083764842589182210659497282698612208183873560479153198260438;
//     uint256 constant IC9y = 14528810007266341592646828839157502919015909105817201673391605874806123161919;
    
//     uint256 constant IC10x = 12943299295281270690349229569525212816500141366458146513859812524643469756436;
//     uint256 constant IC10y = 4082454805674739326621640159258647595756198436705227442711918116990006617207;
    
//     uint256 constant IC11x = 13858242791845798118865925361952875260624548444488341417070481253261675150592;
//     uint256 constant IC11y = 2324403201574792624550034831040063357340793390962701777120265275705537262126;
    
//     uint256 constant IC12x = 11385763288136569705057204324744290672188700337654342925631615893096400136210;
//     uint256 constant IC12y = 18498806184249923425716765589790397967088987347691880633400246718128737083219;
    
//     uint256 constant IC13x = 19622192734728026584814433229433811678544225836415474680530244583448080552357;
//     uint256 constant IC13y = 19777630746240637362990412994719695257796864086292318109665621265248505634376;
    
//     uint256 constant IC14x = 17083870136459448236350299464474677041552922639512877992865538972066922836178;
//     uint256 constant IC14y = 15848342163811379056160165634371491559020606247388358476576058221203799537000;
    
//     uint256 constant IC15x = 10996075264754906499325420327590036438104640694748362486506935903228946360096;
//     uint256 constant IC15y = 9273892473016605847854296090680641865280417176262455786070654947454049046144;
    
//     uint256 constant IC16x = 15886541309255173738689410110489260713870327085119921245364708945018591003847;
//     uint256 constant IC16y = 15609512451964782574944235131808607972416527063775925891912408096744912106770;
    
 
//     // Memory data
//     uint16 constant pVk = 0;
//     uint16 constant pPairing = 128;

//     uint16 constant pLastMem = 896;

//     function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[16] calldata _pubSignals) public view returns (bool) {
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
                
//                 g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
//                 g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
//                 g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
//                 g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
//                 g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
//                 g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
//                 g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
//                 g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
//                 g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
//                 g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
//                 g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
//                 g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
//                 g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
//                 g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                

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
            
//             checkField(calldataload(add(_pubSignals, 64)))
            
//             checkField(calldataload(add(_pubSignals, 96)))
            
//             checkField(calldataload(add(_pubSignals, 128)))
            
//             checkField(calldataload(add(_pubSignals, 160)))
            
//             checkField(calldataload(add(_pubSignals, 192)))
            
//             checkField(calldataload(add(_pubSignals, 224)))
            
//             checkField(calldataload(add(_pubSignals, 256)))
            
//             checkField(calldataload(add(_pubSignals, 288)))
            
//             checkField(calldataload(add(_pubSignals, 320)))
            
//             checkField(calldataload(add(_pubSignals, 352)))
            
//             checkField(calldataload(add(_pubSignals, 384)))
            
//             checkField(calldataload(add(_pubSignals, 416)))
            
//             checkField(calldataload(add(_pubSignals, 448)))
            
//             checkField(calldataload(add(_pubSignals, 480)))
            

//             // Validate all evaluations
//             let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

//             mstore(0, isValid)
//              return(0, 0x20)
//          }
//      }
//  }
