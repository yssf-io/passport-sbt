import { SMT } from '@openpassport/zk-kit-smt';
import { poseidon2 } from 'poseidon-lite';

import namejson from '../../../common/ofacdata/outputs/nameSMT.json';
import {
  circuitToSelectorMode,
  DEFAULT_MAJORITY,
  getCountryCode,
  PASSPORT_ATTESTATION_ID,
} from '../../../common/src/constants/constants';
import {
  ArgumentsDisclose,
  ArgumentsProveOffChain,
  DisclosureOptions,
  OpenPassportApp,
} from '../../../common/src/utils/appType';
import {
  generateCircuitInputsVCandDisclose,
  generateCircuitInputsProve,
} from '../../../common/src/utils/generateInputs';
import { fetchTreeFromUrl } from '../../../common/src/utils/pubkeyTree';
import { revealBitmapFromAttributes } from '../../../common/src/utils/revealBitmap';
import { PassportData } from '../../../common/src/utils/types';

import useUserStore from '../stores/userStore';

export const generateCircuitInputsInApp = async (
  passportData: PassportData,
  app: OpenPassportApp,
): Promise<any> => {
  const { secret, dscSecret } = useUserStore.getState();
  const selector_mode =
    circuitToSelectorMode[app.mode as keyof typeof circuitToSelectorMode];
  let smt = new SMT(poseidon2, true);
  smt.import(namejson);
  switch (app.mode) {
    case 'prove_offchain':
    case 'prove_onchain':
      const disclosureOptions: DisclosureOptions = (
        app.args as ArgumentsProveOffChain
      ).disclosureOptions;
      const selector_dg1 = revealBitmapFromAttributes(disclosureOptions);
      const selector_older_than = disclosureOptions.minimumAge.enabled ? 1 : 0;
      const selector_ofac = disclosureOptions.ofac ? 1 : 0;
      const forbidden_countries_list =
        disclosureOptions.excludedCountries.value.map(country =>
          getCountryCode(country),
        );
      const inputs = generateCircuitInputsProve(
        selector_mode,
        secret,
        dscSecret as string,
        passportData,
        app.scope,
        selector_dg1,
        selector_older_than,
        disclosureOptions.minimumAge.value ?? DEFAULT_MAJORITY,
        smt,
        selector_ofac,
        forbidden_countries_list,
        app.userId,
        app.userIdType,
      );
      return inputs;
    case 'register':
      const selector_dg1_zero = new Array(88).fill(0);
      const selector_older_than_zero = 0;
      const selector_ofac_zero = 0;
      return generateCircuitInputsProve(
        selector_mode,
        secret,
        dscSecret as string,
        passportData,
        app.scope,
        selector_dg1_zero,
        selector_older_than_zero,
        DEFAULT_MAJORITY,
        smt,
        selector_ofac_zero,
        [],
        app.userId,
        app.userIdType,
      );
    case 'vc_and_disclose':
      const commitmentMerkleTreeUrl = (app as any).args.commitmentMerkleTreeUrl;
      const tree = await fetchTreeFromUrl(commitmentMerkleTreeUrl);

      const disclosureOptionsDisclose: DisclosureOptions = (
        app.args as ArgumentsDisclose
      ).disclosureOptions;
      const selector_dg1_disclose = revealBitmapFromAttributes(
        disclosureOptionsDisclose,
      );
      const selector_older_than_disclose = disclosureOptionsDisclose.minimumAge
        .enabled
        ? 1
        : 0;
      const selector_ofac_disclose = disclosureOptionsDisclose.ofac ? 1 : 0;
      const forbidden_countries_list_disclose =
        disclosureOptionsDisclose.excludedCountries.value.map(country =>
          getCountryCode(country),
        );
      return generateCircuitInputsVCandDisclose(
        secret,
        PASSPORT_ATTESTATION_ID,
        passportData,
        app.scope,
        selector_dg1_disclose,
        selector_older_than_disclose,
        tree,
        disclosureOptionsDisclose.minimumAge.value ?? DEFAULT_MAJORITY,
        smt,
        selector_ofac_disclose,
        forbidden_countries_list_disclose,
        app.userId,
      );
  }
};
