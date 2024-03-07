/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_blind_challenge,
  calculate_random_scalars,
  commitment_with_proof_to_octets,
  create_generators,
  messages_to_scalars,
  mocked_calculate_random_scalars
} from './util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export async function commit({
  committed_messages, api_id = new Uint8Array(), ciphersuite,
  mocked_random_scalars_options
} = {}) {
  // FIXME: handle `api_id`

  /* Algorithm:

  1.  M = length(committed_messages)
  2.  generators = BBS.create_generators(M + 2, api_id)
  3.  (Q_2, J_1, ..., J_M) = generators[1..M+1]
  4.  (msg_1, ..., msg_M) = BBS.messages_to_scalars(committed_messages,
                                                    api_id)
  5.  (secret_prover_blind, s~, m~_1, ..., m~_M) = BBS.get_random_scalars(M + 2)
  6.  C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  7.  Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  8.  challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  9.  s^ = s~ + secret_prover_blind * challenge
  10. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  11. proof = (s^, (m^_1, ..., m^_M), challenge)
  12. commit_with_proof_octs = commitment_with_proof_to_octets(C, proof)
  13. return (commit_with_proof_octs, secret_prover_blind)

  */
  const M = committed_messages.length;
  const generators = create_generators({count: M + 2, api_id, ciphersuite});
  const {Q_1: Q_2, H: J} = generators;
  const msgs = messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  });
  const random_scalars = mocked_random_scalars_options === undefined ?
    await calculate_random_scalars({count: M + 2, ciphersuite}) :
    mocked_calculate_random_scalars({
      count: M + 2, ...mocked_random_scalars_options, ciphersuite
    });
  // `~` expressed as `_` here
  const [secret_prover_blind, s_, ...ms_] = random_scalars;

  // C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  let C = Q_2.multiply(secret_prover_blind);
  for(let i = 0; i < msgs.length; ++i) {
    C = C.add(J[i].multiply(msgs[i]));
  }

  // Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  let Cbar = Q_2.multiply(s_);
  for(let i = 0; i < ms_.length; ++i) {
    Cbar = Cbar.add(J[i].multiply(ms_[i]));
  }

  // challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  const challenge = calculate_blind_challenge({
    C, Cbar, generators, api_id, ciphersuite
  });

  // s^ = s~ + secret_prover_blind * challenge
  // arithmetic here is with scalars only (not points) so perform in field `Fr`
  const {Fr} = ciphersuite;
  const sHat = Fr.add(s_, Fr.mul(secret_prover_blind, challenge));

  // for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  const mHats = new Array(ms_.length);
  for(let i = 0; i < ms_.length; ++i) {
    mHats[i] = Fr.add(ms_[i], Fr.mul(msgs[i], challenge));
  }

  const proof = [sHat, ...mHats, challenge];
  const commit_with_proof_octs = commitment_with_proof_to_octets({
    commitment: C, proof, ciphersuite
  });

  return [commit_with_proof_octs, secret_prover_blind];
}

export function verify_commitment({} = {}) {
  // FIXME: implement

}
