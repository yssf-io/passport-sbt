import { PassportMetadata } from "./passports/passport_parsing/parsePassportData";

export type PassportData = {
  mrz: string;
  dg1Hash?: number[];
  dg2Hash?: number[];
  dgPresents?: any[];
  dsc: string;
  eContent: number[];
  signedAttr: number[];
  encryptedDigest: number[];
  photoBase64: string;
  mockUser?: boolean;
  parsed: boolean;
  passportMetadata?: PassportMetadata;
  dsc_parsed?: any;
  csca_parsed?: any;
};

// Define the signature algorithm in "algorithm_hashfunction_domainPapameter_keyLength"
export type SignatureAlgorithm =
  | 'rsa_sha1_65537_2048'
  | 'rsa_sha256_65537_2048'
  | 'rsapss_sha256_65537_2048'
  | 'rsapss_sha256_3_4096'
  | 'rsapss_sha256_3_3072'
  | 'rsapss_sha384_65537_3072'
  | 'rsapss_sha384_65537_4096'
  | 'rsa_sha256_3_4096'
  | 'rsa_sha512_65537_2048'
  | 'rsa_sha1_65537_4096'
  | 'ecdsa_sha256_secp256r1_256'
  | 'ecdsa_sha1_secp256r1_256'
  | 'ecdsa_sha384_secp384r1_384'
  | 'ecdsa_sha256_brainpoolP256r1_256'
  | 'rsa_sha256_3_2048'
  | 'rsa_sha256_65537_3072'
  | 'rsa_sha256_65537_4096'
  | 'rsa_sha512_65537_4096'
  | 'rsa_sha224_65537_2048'
  | 'rsapss_sha256_65537_3072'
  | 'rsapss_sha256_65537_4096'
  | 'rsapss_sha256_3_2048'
  | 'rsapss_sha512_3_4096'
  | 'rsapss_sha512_3_2048'
  | 'rsapss_sha384_3_4096'
  | 'rsapss_sha384_3_3072'
  | 'ecdsa_sha256_secp384r1_384'
  | 'ecdsa_sha384_brainpoolP256r1_256'
  | 'ecdsa_sha512_brainpoolP256r1_256'
  | 'ecdsa_sha384_brainpoolP384r1_384'
  | 'ecdsa_sha512_brainpoolP384r1_384'
  | 'ecdsa_sha1_brainpoolP224r1_224'
  | 'ecdsa_sha224_brainpoolP224r1_224'
  | 'ecdsa_sha256_brainpoolP224r1_224'
  | 'ecdsa_sha512_brainpoolP512r1_512';

export type Proof = {
  proof: {
    a: [string, string];
    b: [[string, string], [string, string]];
    c: [string, string];
  };
  pub_signals: string[];
};

export function castCSCAProof(proof: any): Proof {
  return {
    proof: {
      a: proof.proof.pi_a.slice(0, 2),
      b: [proof.proof.pi_b[0].slice(0, 2), proof.proof.pi_b[1].slice(0, 2)],
      c: proof.proof.pi_c.slice(0, 2),
    },
    pub_signals: proof.pub_signals,
  };
}
