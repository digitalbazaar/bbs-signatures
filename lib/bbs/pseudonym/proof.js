/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  concatBytes, hash_to_scalar, i2osp, serialize, TEXT_ENCODER
} from '../util.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

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

  1. hash_to_scalar_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const hash_to_scalar_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. R = length(disclosed_indexes)
  2. (i1, ..., iR) = disclosed_indexes
  3. (msg_i1, ..., msg_iR) = disclosed_messages
  4. (Abar, Bbar, D, T1, T2, domain) = init_res
  5. (pseudonym, OP, Ut) = pseudonym_init_res

  ABORT if:

  1. R > 2^64 - 1
  2. length(ph) > 2^64 - 1

  */
  const R = disclosed_indexes.length;
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const [pseudonym, OP, Ut] = pseudonym_init_res;
  if(!Number.isSafeInteger(R)) {
    throw new Error(
      `"disclosed_indexes.length" (${R}) must be a safe integer.`);
  }
  if(!Number.isSafeInteger(ph.length)) {
    throw new Error(`"ph.length" (${ph.length}) must be a safe integer.`);
  }

  /* Algorithm:

  1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR,
              Abar, Bbar, D, T1, T2, pseudonym, OP, Ut, domain)
  2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  3. return hash_to_scalar(c_octs, challenge_dst)

  */

  // "zip" indexes and messages together and then flatten
  const zipped = disclosed_indexes.map(
    (x, i) => [x, disclosed_messages[i]]).flat();
  const c_arr = [
    R, ...zipped,
    Abar, Bbar, D, T1, T2, pseudonym, OP, Ut, domain];
  const c_octs = concatBytes(
    serialize({input_array: c_arr, ciphersuite}), i2osp(ph.length, 8), ph);
  return hash_to_scalar({
    msg_octets: c_octs,
    dst: hash_to_scalar_dst,
    ciphersuite
  });
}
