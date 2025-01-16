/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_blind_challenge,
  commitment_with_proof_to_octets,
} from './util.js';
import {
  calculate_domain,
  calculate_random_scalars,
  concatBytes,
  concatGenerators,
  hash_to_scalar,
  mocked_calculate_random_scalars,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export async function CoreCommit({
  blind_generators, committed_message_scalars, api_id, ciphersuite,
  mocked_random_scalars_options
} = {}) {
  /* Deserialization:

  1. M = length(committed_messages)
  2. if length(blind_generators) != M + 1, return INVALID
  3. (Q_2, J_1, ..., J_M) = blind_generators

  */
  const M = committed_message_scalars.length;
  if(blind_generators.length !== (M + 1)) {
    throw new Error(
      `"blind_generators.length" (${blind_generators.length}) must equal ` +
      '"commited_message_scalars.length" ' +
      `(${committed_message_scalars.length}) + 1.`);
  }
  const [Q_2, ...J] = blind_generators;
  const msg = committed_message_scalars;

  /* Algorithm:

  1. (secret_prover_blind, s~, m~_1, ..., m~_M) = BBS.get_random_scalars(M + 2)
  2. C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  3. Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  4. challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  5. s^ = s~ + secret_prover_blind * challenge
  6. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  7. proof = (s^, (m^_1, ..., m^_M), challenge)
  8. commit_with_proof_octs = commitment_with_proof_to_octets(C, proof)
  9. return (commit_with_proof_octs, secret_prover_blind)

  */
  const random_scalars = mocked_random_scalars_options === undefined ?
    await calculate_random_scalars({count: M + 2, ciphersuite}) :
    mocked_calculate_random_scalars({
      count: M + 2, ...mocked_random_scalars_options, ciphersuite
    });
  // `~` expressed as `_` here
  const [secret_prover_blind, s_, ...m_] = random_scalars;

  // C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  let C = Q_2.multiply(secret_prover_blind);
  for(let i = 0; i < msg.length; ++i) {
    C = C.add(J[i].multiply(msg[i]));
  }

  // Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  let Cbar = Q_2.multiply(s_);
  for(let i = 0; i < m_.length; ++i) {
    Cbar = Cbar.add(J[i].multiply(m_[i]));
  }

  // challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  const challenge = calculate_blind_challenge({
    C, Cbar, generators: blind_generators, api_id, ciphersuite
  });

  // s^ = s~ + secret_prover_blind * challenge
  // arithmetic here is with scalars only (not points) so perform in field `Fr`
  const {Fr} = ciphersuite;
  const sHat = Fr.add(s_, Fr.mul(secret_prover_blind, challenge));

  // for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  const mHat = new Array(m_.length);
  for(let i = 0; i < m_.length; ++i) {
    mHat[i] = Fr.add(m_[i], Fr.mul(msg[i], challenge));
  }

  const proof = [sHat, ...mHat, challenge];
  const commit_with_proof_octs = commitment_with_proof_to_octets({
    commitment: C, proof, ciphersuite
  });

  // FIXME: consider passing in `secret_prover_blind` instead of generating
  // it internally; or perhaps return object instead
  return [commit_with_proof_octs, secret_prover_blind];
}

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
