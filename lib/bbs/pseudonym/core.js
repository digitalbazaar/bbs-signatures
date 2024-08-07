/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_random_scalars,
  mocked_calculate_random_scalars,
  octets_to_proof, octets_to_pubkey, octets_to_signature
} from '../util.js';
import {
  ProofFinalize,
  ProofInit, ProofVerifyInit
} from '../proof.js';
import {ProofWithPseudonymChallengeCalculate} from './proof.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export async function CoreProofGenWithPseudonym({
  PK, signature,
  Pseudonym, verifier_id, pid_scalar,
  generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite, mocked_random_scalars_options
} = {}) {
  /* Note: The only difference between this and `CoreProofGenWithPseudonym` is
  the appending of `pid_scalar` to `messages` prior to their use and the
  generation of `pseudo_init_res` to be passed to
  `ProofWithPseudonymChallengeCalculate`. */

  /* Deserialization:

  1.  signature_result = octets_to_signature(signature)
  2.  if signature_result is INVALID, return INVALID
  3.  (A, e) = signature_result
  4.  messages = messages.push(pid_scalar)
  5.  L = length(messages)
  6.  R = length(disclosed_indexes)
  7.  if R > L, return INVALID
  8.  U = L - R
  9.  for i in disclosed_indexes, if i < 0 or i > L - 1, return INVALID
  10. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  11. (i1, ..., iR) = disclosed_indexes
  12. (j1, ..., jU) = undisclosed_indexes
  13. disclosed_messages = (messages[i1], ..., messages[iR])
  14. undisclosed_messages = (messages[j1], ..., messages[jU])

  */
  const signature_result = octets_to_signature(
    {signature_octets: signature, ciphersuite});
  messages = messages.slice();
  messages.push(pid_scalar);
  const L = messages.length;
  const R = disclosed_indexes.length;
  if(R > L) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_indexes.length}) must be ` +
      `less than or equal to "messages.length" (${messages.length}).`);
  }
  const U = L - R;
  if(disclosed_indexes.some(i => isNaN(i) || i < 0 || i >= L)) {
    throw new Error(
      `Every index in "disclosed_indexes" (${disclosed_indexes}) ` +
      `must be a number >= 0 and <= ${L}.`);
  }
  const undisclosed_indexes = [];
  const disclosed_messages = [];
  const undisclosed_messages = [];
  const disclosed_indexes_set = new Set(disclosed_indexes);
  // always generate disclosed messages in the same order as messages
  for(const [i, e] of messages.entries()) {
    if(disclosed_indexes_set.has(i)) {
      disclosed_messages.push(e);
    } else {
      undisclosed_indexes.push(i);
      undisclosed_messages.push(e);
    }
  }

  /* Algorithm:

  1. random_scalars = calculate_random_scalars(5+U)
  2. init_res = ProofInit(
                  PK, signature_result, generators, random_scalars,
                  header, messages, undisclosed_indexes, api_id)
  3. if init_res is INVALID, return INVALID
  4. OP = hash_to_curve_g1(verifier_id)
  5. pid~ = random_scalars[5+U] // last element of random_scalars
  6. U = OP * pid~
  7. pseudonym_init_res = (Pseudonym, OP, U)
  8. challenge = ProofWithPseudonymChallengeCalculate(
                   init_res, pseudonym_init_res,
                   disclosed_indexes, disclosed_messages, ph)
  9. if challenge is INVALID, return INVALID
  10. proof = ProofFinalize(init_res, challenge, e, random_scalars,
                           undisclosed_messages)
  11. return proof

  */
  const random_scalars = mocked_random_scalars_options === undefined ?
    await calculate_random_scalars({count: 5 + U, ciphersuite}) :
    mocked_calculate_random_scalars({
      count: 5 + U, ...mocked_random_scalars_options, ciphersuite
    });
  const init_res = ProofInit({
    PK, signature_result, generators, random_scalars, header,
    messages, undisclosed_indexes, api_id, ciphersuite
  });
  // generate `pseudonym_init_res`
  const OP = ciphersuite.hash_to_curve_g1(verifier_id, api_id);
  // `pid_` means `pid~` here
  const pid_ = random_scalars[5 + U];
  // note: `U` used twice but is a point here, not message length difference,
  // so renamed to `U_`
  const U_ = OP.multiply(pid_);
  const pseudonym_init_res = [Pseudonym, OP, U_];
  // generate challenge
  const challenge = ProofWithPseudonymChallengeCalculate({
    init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  const [, e] = signature_result;
  const proof = ProofFinalize({
    init_res, challenge, e_value: e, random_scalars, undisclosed_messages,
    ciphersuite
  });
  return proof;
}

export function CoreProofVerifyWithPseudonym({
  PK, proof,
  Pseudonym, verifier_id,
  generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  disclosed_messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Note: The only difference between this and `CoreProofVerify` is the
  generation of `pseudonym_init_res` from `Pseudonym`, `verifier_id`, and
  the last commitment in the proof and passing this generated array of
  components to `ProofWithPseudonymChallengeCalculate` instead of using
  `ProofChallengeCalculate` to create the challenge. */

  /* Deserialization:

  1. proof_result = octets_to_proof(proof)
  2. if proof_result is INVALID, return INVALID
  3. (Abar, Bbar, D, e^, r1^, r3^, commitments, cp) = proof_result
  4. W = octets_to_pubkey(PK)
  5. if W is INVALID, return INVALID

  */
  const proof_result = octets_to_proof({proof_octets: proof, ciphersuite});
  const [Abar, Bbar] = proof_result;
  // `pid^` used below is the last commitment
  const pidHat = proof_result.at(-2);
  const cp = proof_result.at(-1);
  const W = octets_to_pubkey({PK, ciphersuite});

  /* Algorithm:

  1. init_res = ProofVerifyInit(PK, proof_result, generators, header,
                                messages, disclosed_indexes, api_id)
  2. if init_res is INVALID, return INVALID
  3. OP = hash_to_curve_g1(verifier_id)
  4.  pid^ = commitments[-1] // last element of the commitments
  5.  Uv = OP * pid^ - Pseudonym * cp
  6.  pseudonym_init_res = (Pseudonym, OP, Uv)
  7. challenge = ProofWithPseudonymChallengeCalculate(
                   init_res, pseudonym_init_res,
                   disclosed_indexes, messages, ph, api_id)
  8. if challenge is INVALID, return INVALID
  9. if cp != challenge, return INVALID
  10. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  11. return VALID

  */
  const init_res = ProofVerifyInit({
    PK, proof: proof_result, generators, header,
    disclosed_messages, disclosed_indexes,
    api_id, ciphersuite
  });
  // generate `pseudonym_init_res`
  const OP = ciphersuite.hash_to_curve_g1(verifier_id, api_id);
  const Uv = OP.multiply(pidHat).subtract(Pseudonym.multiply(cp));
  const pseudonym_init_res = [Pseudonym, OP, Uv];
  // generate challenge
  const challenge = ProofWithPseudonymChallengeCalculate({
    init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  if(cp !== challenge) {
    // proof challenge does not match
    return false;
  }
  // performs step 6 more efficiently;
  // note that BP2 will be negated internally to -BP2 to perform the comparison
  // by multiplying the pairings and checking against Identity_GT as above
  const {BP2} = ciphersuite;
  const pair1 = [Abar, W];
  const pair2 = [Bbar, BP2];
  return ciphersuite.eCompare({pair1, pair2});
}
