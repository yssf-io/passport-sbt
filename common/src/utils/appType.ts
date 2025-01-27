import { UserIdType } from "./circuits/uuid";

export type CircuitName = 'prove' | 'disclose';
export type CircuitMode = 'prove_onchain' | 'register' | 'prove_offchain';
export type Mode = 'prove_offchain' | 'prove_onchain' | 'register' | 'vc_and_disclose' | 'dsc';

// OpenPassportAppType
export interface OpenPassportAppPartial {
  mode: Mode;
  appName: string;
  scope: string;
  websocketUrl: string;
  sessionId: string;
  userId: string;
  userIdType: UserIdType;
  devMode: boolean;
}

export interface OpenPassportApp extends OpenPassportAppPartial {
  args: ArgumentsProveOffChain | ArgumentsProveOnChain | ArgumentsRegister | ArgumentsDisclose;
}

export interface ArgumentsProveOffChain {
  disclosureOptions: DisclosureOptions;
}

export interface ArgumentsProveOnChain {
  disclosureOptions: DisclosureOptions;
  modalServerUrl: string;
  merkleTreeUrl: string;
}

export interface ArgumentsRegister {
  cscaMerkleTreeUrl: string;
  commitmentMerkleTreeUrl: string;
  modalServerUrl: string;
}

export interface ArgumentsDisclose {
  disclosureOptions: DisclosureOptions;
  commitmentMerkleTreeUrl: string;
}

export interface DisclosureOptions {
  minimumAge: { enabled: boolean; value: string };
  nationality: { enabled: boolean; value: string };
  excludedCountries: { enabled: boolean; value: string[] };
  ofac: boolean;
}
