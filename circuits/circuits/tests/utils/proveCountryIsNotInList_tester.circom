pragma circom 2.1.9;
include "../../utils/passport/disclose/proveCountryIsNotInList.circom";
component main { public [ forbidden_countries_list ] } = ProveCountryIsNotInList(10);
