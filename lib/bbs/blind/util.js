/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  concatBytes, hash_to_scalar, os2ip, serialize, TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function calculate_blind_challenge({
  C, Cbar, generators, api_id, ciphersuite
} = {}) {
  /* Definitions:

  1. blind_challenge_dst, an octet string representing the domain
                          separation tag: api_id || "H2S_" where
                          ciphersuite_id is defined by the ciphersuite and
                          "H2S_" is an ASCII string composed of 4 bytes.

  Deserialization:

  1. if length(generators) == 0, return INVALID
  2. M = length(generators) - 1

  */
  const blind_challenge_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));
  const M = generators.length - 1;

  /* Algorithm:

  1. c_arr = (C, Cbar, M)
  2. c_arr.append(generators)
  3. c_octs = serialize(c_arr)
  4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)

  */
  const c_arr = [C, Cbar, M, ...generators];
  const c_octs = serialize({input_array: c_arr, ciphersuite});
  return hash_to_scalar({
    msg_octets: c_octs, dst: blind_challenge_dst, ciphersuite
  });
}

export function commitment_with_proof_to_octets({
  commitment, proof, ciphersuite
} = {}) {
  /* Algorithm:

  1. commitment_octs = serialize(commitment)
  2. if commitment_octs is INVALID, return INVALID
  3. proof_octs = serialize(proof)
  4. if proof_octs is INVALID, return INVALID
  5. return commitment_octs || proof_octs

  */
  const commitment_octs = serialize({input_array: [commitment], ciphersuite});
  const proof_octs = serialize({input_array: proof, ciphersuite});
  return concatBytes(commitment_octs, proof_octs);
}

export function get_disclosed_data({
  messages, disclosed_indexes,
  committed_messages, disclosed_commitment_indexes,
  secret_prover_blind
} = {}) {
  /* Deserialization:

  1. L = length(messages)
  2. M = length(committed_messages)
  3. (i1, ..., iL) = disclosed_indexes
  4. (j1, ...., jL) = disclosed_commitment_indexes
  5. if length(disclosed_indexes) > L, return INVALID
  6. if length(disclosed_commitment_indexes) > M, return INVALID

  */
  // other checks above are indirectly performed via `CoreProofGen`
  const M = committed_messages.length;

  /* Algorithm:

  // determine if a commitment was used
  1. if secret_prover_blind == 0, comm_used = 0, else comm_used = 1

  // combine the disclosed indexes
  2. indexes = ()
  3. for i in disclosed_commitment_indexes: indexes.append(i + comm_used)
  4. for j in disclosed_indexes: indexes.append(M + j + comm_used)

  // combine the disclosed messages
  5. disclosed_messages = (messages[i1], ..., messages[iL])
  6. disclosed_committed_messages = (committed_messages[j1], ...
                                              ..., committed_messages[jM])
  7. disclosed_messages.append(disclosed_committed_messages)

  8. return (disclosed_messages, indexes)

  */
  // determine if a commitment was used
  const comm_used = secret_prover_blind === 0n ? 0 : 1;

  // combine the disclosed indexes
  const indexes = [
    ...disclosed_commitment_indexes.map(i => i + comm_used),
    ...disclosed_indexes.map(j => M + j + comm_used)];

  // combine to get the total messages
  // FIX to spec: spec has these in reverse order here vs. `BlindProofGen`
  const total_messages = [
    ...committed_messages,
    ...messages
  ];

  // FIX to spec: the spec uses the name `disclosed_messages` here, but these
  // are ALL the messages, disclosed or not -- and `disclosed_indexes`
  // identifies the corresponding `message_scalars` that match, they are not
  // indexes into `total_messages`
  return {messages: total_messages, disclosed_indexes: indexes};
}

export function octets_to_commitment_with_proof({
  commitment_with_proof_octets, ciphersuite
} = {}) {
  /* Algorithm:

  1.  commit_len_floor = octet_point_length + 2 * octet_scalar_length
  2.  if length(commitment) < commit_len_floor, return INVALID

  3.  C_octets = commitment_octs[0..(octet_point_length - 1)]
  4.  C = octets_to_point_g1(C_octets)
  5.  if C is INVALID, return INVALID
  6.  if C == Identity_G1, return INVALID

  7.  j = 0
  8.  index = octet_point_length
  9.  while index < length(commitment_octs):
  10.     end_index = index + octet_scalar_length - 1
  11.     s_j = OS2IP(proof_octets[index..end_index])
  12.     if s_j = 0 or if s_j >= r, return INVALID
  13.     index += octet_scalar_length
  14.     j += 1

  15. if index != length(commitment_octs), return INVALID
  16. if j < 2, return INVALID
  17. msg_commitment = ()
  18. if j >= 3, set msg_commitment = (s_2, ..., s_(j-1))
  19. return (C, (s_0, msg_commitments, s_j))

  */
  const {r, octet_point_length, octet_scalar_length} = ciphersuite;
  const commit_len_floor = octet_point_length + 2 * octet_scalar_length;
  if(commitment_with_proof_octets.length < commit_len_floor) {
    throw new Error(
      '`"commitment_with_proof_octets.length" ' +
      `(${commitment_with_proof_octets.length}) ` +
      `must be at least ${commit_len_floor}.`);
  }

  const C_octets = commitment_with_proof_octets.subarray(
    0, octet_point_length);
  const C = ciphersuite.octets_to_point_E1(C_octets);
  if(C.equals(ciphersuite.Identity_E1)) {
    throw new Error('Invalid point in commitment.');
  }

  // simplified steps 7-14:
  // proof follows commitment point
  const proof_octets = commitment_with_proof_octets.subarray(
    octet_point_length);
  let index = 0;
  const proof = [];
  while(index < proof_octets.length) {
    const s_j = os2ip(
      proof_octets.subarray(index, index + octet_scalar_length));
    if(s_j === 0 || s_j >= r) {
      throw new Error('Invalid scalar in proof.');
    }
    proof.push(s_j);
    index += octet_scalar_length;
  }

  // check proof size is valid
  if(proof.length < 2 || index !== proof_octets.length) {
    throw new Error('Invalid proof size.');
  }

  return {commitment: C, proof};
}
