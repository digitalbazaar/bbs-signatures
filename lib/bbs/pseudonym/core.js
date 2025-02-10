/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
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

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export async function CoreProofGenWithPseudonym({
  PK, signature,
  context_id,
  generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  // FIXME: uniformly adjust `messages` to `message_scalars` wherever this
  // parameter represents message scalars and not the messages themselves,
  // even if the BBS spec names are inconsistent it will be more useful in
  // this implementation to be more clear
  messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite, mocked_random_scalars_options
} = {}) {
  /* Note: The only difference between `CoreProofGenWithPseudonym` and
  `CoreProofGen` is the generation of `pseudo_init_res` to be passed to
  `ProofWithPseudonymChallengeCalculate`. */

  /* Deserialization:

  1.  signature_result = octets_to_signature(signature)
  2.  if signature_result is INVALID, return INVALID
  3.  (A, e) = signature_result
  4.  L = length(messages)
  5.  R = length(disclosed_indexes)
  6.  (i1, ..., iR) = disclosed_indexes
  7.  if R > L - 1, return INVALID, Note: we never reveal the `nym_secret`.
  8.  U = L - R
  // Note: `nym_secret` is last message and must never be revealed. Also, the
  // next step is expressed as "Abort" in the spec and inserted here below.
  // FIX to spec: `i` must not be L - 1 either, as this is the `nym_secret`.
  9.  for i in disclosed_indexes, if i < 0 or i > L - 2, return INVALID
  10. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  11. (i1, ..., iR) = disclosed_indexes
  12. (j1, ..., jU) = undisclosed_indexes
  13. disclosed_messages = (messages[i1], ..., messages[iR])
  14. undisclosed_messages = (messages[j1], ..., messages[jU])

  */
  const signature_result = octets_to_signature(
    {signature_octets: signature, ciphersuite});
  const L = messages.length;
  const R = disclosed_indexes.length;
  // subtract `1` from `L` because the `pid` must never be revealed
  if(R > (L - 1)) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_indexes.length}) must be ` +
      `less than or equal to "messages.length" (${messages.length}) - 1.`);
  }
  const U = L - R;
  if(disclosed_indexes.some(i => isNaN(i) || i < 0 || i >= (L - 1))) {
    throw new Error(
      `Every index in "disclosed_indexes" (${disclosed_indexes}) ` +
      `must be a number in the range [0, ${L - 1}).`);
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
  2. init_res = BBS.ProofInit(
                  PK, signature_result, generators, random_scalars,
                  header, messages, undisclosed_indexes, api_id)
  3. if init_res is INVALID, return INVALID
  4. pseudonym_init_res = PseudonymProofInit(
                            context_id, message_scalars[-1], random_scalars[-1])
  5. if pseudonym_init_res is INVALID, return INVALID
  6. pseudonym = pseudonym_init_res[0]
  7. challenge = ProofWithPseudonymChallengeCalculate(
                   init_res, pseudonym_init_res,
                   disclosed_indexes, disclosed_messages, ph, api_id)
  8. proof = BBS.ProofFinalize(
               init_res, challenge, e, random_scalars, undisclosed_messages)
  9. return (proof, pseudonym)

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
  const pseudonym_init_res = PseudonymProofInit({
    context_id,
    nym_secret: messages.at(-1), random_scalar: random_scalars.at(-1),
    api_id, ciphersuite
  });

  // get `pseudonym` as octets
  const pseudonym = ciphersuite.point_to_octets_E1(pseudonym_init_res[0]);

  // generate challenge
  const challenge = ProofWithPseudonymChallengeCalculate({
    init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  const [, e] = signature_result;
  const proof = await ProofFinalize({
    init_res, challenge, e_value: e, random_scalars, undisclosed_messages,
    ciphersuite
  });
  return {proof, pseudonym};
}

export function CoreProofVerifyWithPseudonym({
  PK, proof,
  pseudonym, context_id,
  generators,
  header = new Uint8Array(), ph = new Uint8Array(),
  disclosed_messages = [], disclosed_indexes = [],
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Note: The only difference between `CoreProofVerifyWithPseudonym` and
  `CoreProofVerify` is the generation of `pseudonym_init_res` from
  `pseudonym`, `context_id`, and the last commitment in the proof and passing
  this generated array of components to `ProofWithPseudonymChallengeCalculate`
  instead of using `ProofChallengeCalculate` to create the challenge. If
  `init_res` were generalized to have any number of items with `domain` always
  last, then all the same functions could be used. */

  /* Deserialization:

  1. proof_result = octets_to_proof(proof)
  2. if proof_result is INVALID, return INVALID
  // FIX to spec: proof_result updated below in step 3
  3. (Abar, Bbar, D, e^, r1^, r3^, commitments, c) = proof_result
  4. W = octets_to_pubkey(PK)
  5. if W is INVALID, return INVALID
  6. R = length(disclosed_indexes)
  7. (i1, ..., iR) = disclosed_indexes
  // FIX to spec: should this be `i < 0`? perhaps left over from `pid` being
  // in the first position in an old version?
  8. for i in disclosed_indexes, i < 1 or i > R + length(commitments) - 1,
     return INVALID

  */
  const proof_result = octets_to_proof({proof_octets: proof, ciphersuite});
  const [Abar, Bbar] = proof_result;
  // `nym_secret_commitment` is always the last commitment
  const nym_secret_commitment = proof_result.at(-2);
  const proof_challenge = proof_result.at(-1);
  const W = octets_to_pubkey({PK, ciphersuite});
  const R = disclosed_indexes.length;
  // length of commitments (proof_result has 7 values other than commitments)
  const U = proof_result.length - 7;
  if(disclosed_indexes.some(i => isNaN(i) || i < 0 || i > (R + U - 1))) {
    throw new Error(
      `Every index in "disclosed_indexes" (${disclosed_indexes}) ` +
      `must be a number in the range [0, ${R + U - 1}).`);
  }

  /* Algorithm:

  1. init_res = BBS.ProofVerifyInit(
                  PK, proof_result, generators, header,
                  messages, disclosed_indexes, api_id)
  2. pseudonym_init_res = PseudonymProofVerifyInit(
                            Pseudonym, context_id, commitments[-1], cp)
  3. if pseudonym_init_res is INVALID, return INVALID
  4. challenge = ProofWithPseudonymChallengeCalculate(
                  init_res, pseudonym_init_res,
                  disclosed_indexes, messages, ph, api_id)
  5. if cp != challenge, return INVALID
  6. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  7. return VALID

  */
  const init_res = ProofVerifyInit({
    PK, proof: proof_result, generators, header,
    disclosed_messages, disclosed_indexes,
    api_id, ciphersuite
  });
  const pseudonym_init_res = PseudonymProofVerify({
    pseudonym, context_id, nym_secret_commitment, proof_challenge,
    api_id, ciphersuite
  });
  // generate challenge
  const challenge = ProofWithPseudonymChallengeCalculate({
    init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_messages, ph, api_id, ciphersuite
  });
  if(proof_challenge !== challenge) {
    // proof challenge does not match
    return false;
  }
  // performs step 6 more efficiently;
  // note that BP2 will be negated internally to -BP2 to perform the comparison
  // by multiplying the pairings and checking against Identity_GT as above
  const {BP2} = ciphersuite;
  const pair1 = [Abar, W];
  const pair2 = [Bbar, BP2];
  return ciphersuite.pairingCompare({pair1, pair2});
}

export function PseudonymProofInit({
  context_id, nym_secret, random_scalar,
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Algorithm:

  1. OP = hash_to_curve_g1(context_id, api_id)
  2. Pseudonym = OP * nym_secret
  3. Ut = OP * random_scalar
  4. if Pseudonym == Identity_G1 or Ut == Identity_G1, return INVALID
  5. return (Pseudonym, OP, Ut)

  */
  const OP = ciphersuite.hash_to_curve_g1(context_id, api_id);
  const pseudonym = OP.multiply(nym_secret);
  const Ut = OP.multiply(random_scalar);
  // if pseudonym == Identity_G1 or Ut == Identity_G1 throw invalid pseudonym
  if(pseudonym.equals(ciphersuite.Identity_E1) ||
    Ut.equals(ciphersuite.Identity_E1)) {
    throw new Error('Invalid pseudonym.');
  }
  return [pseudonym, OP, Ut];
}

export function PseudonymProofVerify({
  pseudonym, context_id, nym_secret_commitment, proof_challenge,
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Algorithm:

  1. OP = hash_to_curve_g1(context_id)
  2. Uv = OP * nym_secret_commitment - Pseudonym * proof_challenge
  3. if Uv == Identity_G1, return INVALID
  4. return (Pseudonym, OP, Uv)

  */
  const OP = ciphersuite.hash_to_curve_g1(context_id, api_id);
  const Uv = OP.multiply(nym_secret_commitment).subtract(
    pseudonym.multiply(proof_challenge));
  // if Uv == Identity_G1 throw invalid pseudonym challenge
  if(Uv.equals(ciphersuite.Identity_E1)) {
    throw new Error('Invalid pseudonym challenge.');
  }
  return [pseudonym, OP, Uv];
}
