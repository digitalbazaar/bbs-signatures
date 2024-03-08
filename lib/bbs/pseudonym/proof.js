/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  concatBytes, hash_to_scalar, i2osp, serialize, TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function ProofWithPseudonymChallengeCalculate({
  init_res,
  pseudonym_init_res,
  disclosed_indexes = [], disclosed_messages = [], ph = new Uint8Array(),
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Note: The only difference between this and `ProofChallengeCalculate` is
  the insertion of the components in `pseudonym_init_res` after the components
  of `init_res` (modulo the last one, `domain`) into `c_arr`. */

  /*
  Definitions:

  1. challenge_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const challenge_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. R = length(disclosed_indexes)
  2. (i1, ..., iR) = disclosed_indexes
  3. if length(disclosed_messages) != R, return INVALID
  4. (msg_i1, ..., msg_iR) = disclosed_messages
  5. (Abar, Bbar, D, T1, T2, domain) = init_res
  6. (Pseudonym, OP, U) = pseudonym_init_res

  ABORT if:

  1. R > 2^64 - 1
  2. length(ph) > 2^64 - 1

  */
  const R = disclosed_indexes.length;
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const [Pseudonym, OP, U] = pseudonym_init_res;
  if(!Number.isSafeInteger(R)) {
    throw new Error(
      `"disclosed_indexes.length" (${R}) must be a safe integer.`);
  }
  if(!Number.isSafeInteger(ph.length)) {
    throw new Error(`"ph.length" (${ph.length}) must be a safe integer.`);
  }

  /* Algorithm:

  1. c_arr = (Abar, Bbar, D, T1, T2, Pseudonym, OP, U, R, i1, ..., iR,
              msg_i1, ..., msg_iR, domain)
  2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  3. return hash_to_scalar(c_octs, challenge_dst)

  */
  const c_arr = [
    Abar, Bbar, D, T1, T2, Pseudonym, OP, U, R,
    ...disclosed_indexes, ...disclosed_messages,
    domain
  ];
  const c_octs = concatBytes(
    serialize({input_array: c_arr, ciphersuite}), i2osp(ph.length, 8), ph);
  return hash_to_scalar({msg_octets: c_octs, dst: challenge_dst, ciphersuite});
}
