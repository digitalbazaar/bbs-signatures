/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_domain,
  concatBytes,
  concatGenerators,
  hash_to_scalar,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export function FinalizeBlindSign({
  SK, PK, B, generators, blind_generators = [],
  header = new Uint8Array(),
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. hash_to_scalar_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const hash_to_scalar_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. L = length(generators) - 1
  2. M = length(blind_generators)
  3. if L <= 0 or M <=0, return INVALID
  4. (Q_1, H_1, ..., H_L) = generators
  5. (J_1, ..., J_M) = blind_generators

  /* Algorithm:

  1. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L, J_1, ..., J_M),
                               header, api_id)
  // FIX to spec: since `Q_1 * domain` is mixed into `B` now, do not include
  // it in `e_octs`
  2. e_octs = serialize((SK, B))
  3. e = BBS.hash_to_scalar(e_octs, signature_dst)
  4. A = B * (1 / (SK + e))
  5. return signature_to_octets((A, e))

  */
  const domain = calculate_domain({
    PK, generators: concatGenerators(generators, blind_generators),
    header, api_id, ciphersuite
  });
  // update `B` to add in `Q_1 * domain`
  const {Q_1} = generators;
  B = B.add(Q_1.multiply(domain));

  const input_array = [SK, B];
  const e_octs = serialize({input_array, ciphersuite});
  const e = hash_to_scalar({
    msg_octets: e_octs,
    dst: hash_to_scalar_dst,
    ciphersuite
  });

  // A = B * (1 / (SK + e))
  // multiply `B` by the inverse of `SK + e` within the field over `r`
  const {Fr} = ciphersuite;
  const A = B.multiply(Fr.inv(Fr.add(SK, e)));
  // if A == Identity_G1 throw invalid signature error
  if(A.equals(ciphersuite.Identity_E1)) {
    throw new Error('Invalid signature.');
  }
  return signature_to_octets({signature: [A, e], ciphersuite});
}
