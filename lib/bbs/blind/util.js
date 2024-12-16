/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  concatBytes, hash_to_scalar, os2ip, serialize, TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

// FIXME: attempt to consolidate with core `calculate_B()`
export function blind_B_calculate({
  generators, commitment, message_scalars, ciphersuite
} = {}) {
  /*
  Inputs:

  - generators (REQUIRED), an array of at least one point from the
                           G1 group.
  - commitment (OPTIONAL), a point from the G1 group. If not supplied it
                           defaults to the Identity_G1 point.
  - message_scalars (OPTIONAL), an array of scalar values. If not
                                supplied, it defaults to the empty
                                array ("()").
  Outputs:
  - res, an array of a single element from the G1 subgroup, or INVALID.

  /* Deserialization:

  1. L = length(messages)
  2. if length(generators) != L + 1, return INVALID
  3. (Q_1, H_1, ..., H_L) = generators
  4. (msg_1, ..., msg_L) = messages

  */
  const L = message_scalars.length;
  if(generators.length !== (L + 1)) {
    throw new Error(
      `"generators.length" (${generators.length}) must equal ` +
      `"messages.length" (${message_scalars.length}) + 1.`);
  }
  const {H} = generators;

  /* Algorithm:

  // FIX to spec: `P1` not `Q_1` as `Q_1 * domain` will happen later
  1. B = P1 + H_1 * msg_1 + ... + H_L * msg_L + commitment
  2. if B is Identity_G1, return INVALID
  3. return B

  */
  const {P1} = ciphersuite;
  let B = P1;
  let i = 0;
  for(const message of message_scalars) {
    if(message !== 0n) {
      B = B.add(H[i++].multiply(message));
    }
  }
  const {Identity_E1: Identity_G1} = ciphersuite;
  if(commitment === undefined) {
    commitment = Identity_G1;
  }
  B = B.add(commitment);
  if(B.equals(Identity_G1)) {
    throw new Error('Invalid blind "B" value.');
  }

  return {B};
}

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

  1. c_arr = (M)
  2. c_arr.append(generators)
  3. c_octs = serialize(c_arr.append(C, Cbar))
  4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)

  */
  const c_arr = [M, ...generators, C, Cbar];
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

  // instead of `(C, (s_0, msg_commitments, s_j))`, which is the same as
  // `(C, proof)`, an object is used to express the commitment info:
  return {commitment: C, proof};
}

export function prependBlindApiId({api_id = new Uint8Array()} = {}) {
  return concatBytes(TEXT_ENCODER.encode('BLIND_'), api_id);
}
