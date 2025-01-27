pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";

/// @notice ProveCountryIsNotInList template — used to prove that the user is not from a list of forbidden countries
/// @param MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH Maximum number of countries present in the forbidden countries list
/// @input dg1 Data group 1 of the passport
/// @input forbidden_countries_list Forbidden countries list user wants to prove he is not from
/// @output forbidden_countries_list_packed Packed forbidden countries list — gas optimized

template ProveCountryIsNotInList(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH) {
    signal input dg1[93];
    signal input forbidden_countries_list[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * 3]; 

    signal equality_results[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH][4];
    
    for (var i = 0; i < MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH; i++) {
            equality_results[i][0] <== IsEqual()([dg1[7], forbidden_countries_list[i ]]);
            equality_results[i][1] <== IsEqual()([dg1[8], forbidden_countries_list[i + 1]]); 
            equality_results[i][2] <== IsEqual()([dg1[9], forbidden_countries_list[i + 2]]);
            equality_results[i][3] <==  equality_results[i][0] * equality_results[i][1];
            0 ===  equality_results[i][3] * equality_results[i][2];
    }

    var chunkLength = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * 3);
    signal output forbidden_countries_list_packed[chunkLength]  <== PackBytes(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * 3)(forbidden_countries_list);
}
