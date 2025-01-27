import * as fs from 'fs';
import { buildSMT } from '../../../common/src/utils/trees'

async function build_sancCountry_smt() {
    const sc_list = JSON.parse(fs.readFileSync("../../../common/sanctionedCountries/inputs/sc_list.json") as unknown as string)
    const tree = buildSMT(sc_list, "country");

    console.log("Total pairs of countries processed are : ", tree[0], " over ", sc_list.length)
    console.log("SMT for sc built in " + tree[1] + "ms")

    const scJSON = tree[2].export()

    fs.writeFileSync("../../../common/sanctionedCountries/outputs/sc_SMT.json", JSON.stringify(scJSON));
}

build_sancCountry_smt()