/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance} from '../../assert.js';
import {
  calculate_blind_challenge,
  commitment_with_proof_to_octets,
  octets_to_commitment_with_proof
} from './util.js';
import {
  calculate_random_scalars,
  create_generators,
  createApiId,
  messages_to_scalars,
  mocked_calculate_random_scalars
} from '../util.js';
import {BLIND_API_ID} from '../constants.js';
import {getCiphersuite} from '../ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export async function Commit({
  committed_messages, api_id, ciphersuite,
  mocked_random_scalars_options
} = {}) {
  assertArray(committed_messages, 'committed_messages');
  ciphersuite = getCiphersuite(ciphersuite);

  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');

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
  const challenge_generators = generators.slice(1, M + 2);
  const [Q_2, ...J] = challenge_generators;
  const msg = messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  });
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
    // FIX to spec: should passes sliced generators, not `generators` directly
    C, Cbar, generators: challenge_generators, api_id, ciphersuite
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

  return [commit_with_proof_octs, secret_prover_blind];
}

export function deserialize_and_validate_commit({
  commitment_with_proof,
  generators, api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Algorithm:

  1.  if commitment_with_proof is the empty string (""),
        return (Identity_G1, 0)
  2.  com_res = octets_to_commitment_with_proof(commitment_with_proof)
  3.  if com_res is INVALID, return INVALID
  4.  (commit, commit_proof) = com_res
  5.  M = length(commit_proof[1]) + 1
  6.  if length(generators) < M + 1, return INVALID
  7.  blind_generators = generators[1..M + 1]
  8.  validation_res = verify_commitment(commit, commit_proof,
                                         blind_generators, api_id)
  9.  if validation_res is INVALID, return INVALID
  10. (commitment, M)

  */
  if(commitment_with_proof.length === 0) {
    // Identity_G1 == ciphersuite.Identity_E1
    return [ciphersuite.Identity_E1, 0];
  }

  const {
    commitment, proof: commitment_proof
  } = octets_to_commitment_with_proof({
    commitment_with_proof_octets: commitment_with_proof, ciphersuite
  });

  // in this implementation `commitment_proof` is an array with >= 2 scalars,
  // where the first and last scalars are always present and the middle
  // scalars have a length of >= 0; and `length(commit_proof[1])` from the
  // spec refers to the length of the middle scalars... which we compute here
  // by subtracting the first and last (i.e., `commitment_proof.length - 2`)
  const M = commitment_proof.length - 2 + 1;
  if(generators.length < (M + 1)) {
    throw new Error(
      `"generators.length" (${generators.length}) must be greater or equal ` +
      ` to ${M + 1}.`);
  }

  // blind_generators = generators[1..M + 1]
  // note: number of blind generators needs to `M` here, starting at index 1
  const blind_generators = generators.slice(1, M + 1);

  const validation_res = verify_commitment({
    commitment, commitment_proof, blind_generators, api_id, ciphersuite
  });
  if(!validation_res) {
    throw new Error('Commitment verification failed.');
  }

  return [commitment, M];
}

export function verify_commitment({
  commitment, commitment_proof, blind_generators,
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Deserialization:

  1. (s^, commitments, cp) = commitment_proof
  2. M = length(commitments)
  3. (m^_1, ..., m^_M) = commitments
  4. if length(blind_generators) != M + 1, return INVALID
  5. (Q_2, J_1, ..., J_M) = blind_generators

  */
  const [sHat, ...mHat] = commitment_proof;
  const cp = mHat.pop();
  // M = number of commitments
  const M = mHat.length;
  // number of blind generators must be number of `commitments` + 1
  if(blind_generators.length !== (M + 1)) {
    throw new Error(
      `"blind_generators.length" (${blind_generators.length}) must equal ` +
      `${M + 1}.`);
  }
  const [Q_2, ...J] = blind_generators;

  /* Algorithm:

  1. Cbar = Q_2 * s^ + J_1 * m^_1 + ... + J_M * m^_M + commitment * (-cp)
  2. cv = calculate_blind_challenge(commitment, Cbar, blind_generators, api_id)
  3. if cv != cp, return INVALID
  4. return VALID

  */
  let Cbar = Q_2.multiply(sHat);
  for(let i = 0; i < mHat.length; ++i) {
    Cbar = Cbar.add(J[i].multiply(mHat[i]));
  }
  // `+ commitment * (-cp)` == `- commitment * cp`
  Cbar = Cbar.subtract(commitment.multiply(cp));

  const cv = calculate_blind_challenge({
    C: commitment, Cbar, generators: blind_generators, api_id, ciphersuite
  });
  // return `true` on match, `false` otherwise
  return cv === cp;
}
