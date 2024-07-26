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
import {deserialize_and_validate_commit} from './commitment.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function CoreBlindSign({
  SK, PK, generators, blind_generators = [],
  commitment_with_proof = new Uint8Array(),
  header = new Uint8Array(), message_scalars = [],
  signer_blind = 0n,
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. hash_to_scalar_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const hash_to_scalar_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. L = length(message_scalars)
  2. (msg_1, ..., msg_L) = message_scalars
  3. (Q_1, H_1, ..., H_L) = generators
  4. Q_2 = Identity_G1
  5. if length(blind_generators) > 0, Q_2 = blind_generators[0]
  6. commit = deserialize_and_validate_commit(commitment_with_proof,
                                              blind_generators, api_id)
  7. if commit is INVALID, return INVALID

  */
  const L = message_scalars.length;
  const msgs = message_scalars.slice(0, L);
  const {Q_1} = generators;
  const H = generators.H.slice(0, L);
  // Identity_G1 == ciphersuite.Identity_E1
  const Q_2 = blind_generators.length === 0 ?
    ciphersuite.Identity_E1 : blind_generators[0];
  const commitment = deserialize_and_validate_commit({
    commitment_with_proof, blind_generators, api_id, ciphersuite
  });

  /* Algorithm:

  1. domain = calculate_domain(PK, generators.append(blind_generators),
                               header, api_id)
  2. e_octs = serialize((SK, commitment_with_proof, signer_blind,
                         msg_1, ..., msg_L, domain))
  3. e = BBS.hash_to_scalar(e_octs, hash_to_scalar_dst)
  // if a commitment is not supplied, Q_2 = Identity_G1, meaning that
  // signer_blind will be ignored.
  4. commit = commit + Q_2 * signer_blind
  5. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  6. A = B * (1 / (SK + e))
  7. return signature_to_octets((A, e))
  8. return signature

  */
  const domain = calculate_domain({
    PK, generators: concatGenerators(generators, blind_generators),
    header, api_id, ciphersuite
  });
  const input_array = [SK, commitment_with_proof];
  // only include `signer_blind` when it is non-zero
  // FIX to spec: spec should be explicit about omitting `signer_blind`
  let commit = commitment;
  if(signer_blind !== 0n) {
    input_array.push(signer_blind);
    commit = commit.add(Q_2.multiply(signer_blind));
  }
  input_array.push(...msgs);
  input_array.push(domain);
  const e_octs = serialize({input_array, ciphersuite});
  const e = hash_to_scalar({
    msg_octets: e_octs,
    dst: hash_to_scalar_dst,
    ciphersuite
  });

  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  const {P1} = ciphersuite;
  let B = P1.add(Q_1.multiply(domain));
  let i = 0;
  for(const message of msgs) {
    if(message !== 0n) {
      B = B.add(H[i++].multiply(message));
    }
  }
  B = B.add(commit);

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
