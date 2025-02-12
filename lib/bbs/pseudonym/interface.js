/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../../assert.js';
import {
  concatGenerators, create_generators, createApiId, messages_to_scalars
} from '../util.js';
import {CoreCommit, FinalizeBlindSign} from '../blind/core.js';
import {
  CoreProofGenWithPseudonym,
  CoreProofVerifyWithPseudonym
} from './core.js';
import {B_calculate_with_nym} from './util.js';
import {BlindVerify} from '../blind/interface.js';
import {deserialize_and_validate_commit} from '../blind/commitment.js';
import {getCiphersuite} from '../ciphersuites.js';
import {prependBlindApiId} from '../blind/util.js';
import {PSEUDONYM_API_ID} from '../constants.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export async function BlindSignWithNym({
  SK, PK,
  commitment_with_proof = new Uint8Array(),
  header = new Uint8Array(), messages = [],
  signer_nym_entropy,
  api_id, ciphersuite
} = {}) {
  assertType('bigint', SK, 'SK');
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  assertType('bigint', signer_nym_entropy, 'signer_nym_entropy');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. L = length(messages)

  // calculate the number of blind generators used by the commitment,
  // if any.
  2. M = length(commitment_with_proof)
  // FIX to spec: spec should say `2 * octet_scalar_length`, does not
  // multiply by `2` in draft 3, corrected below in step 3:
  3. if M != 0, M = M - octet_point_length - 2 * octet_scalar_length
  4. M = M / octet_scalar_length
  5. if M < 0, return INVALID

  */
  const L = messages.length;
  let M = commitment_with_proof.length;
  if(M !== 0) {
    const {octet_point_length, octet_scalar_length} = ciphersuite;
    M = M - octet_point_length - 2 * octet_scalar_length;
    if(M < 0 || (M % octet_scalar_length !== 0)) {
      throw new Error(
        `"commitment_with_proof.length" (${commitment_with_proof.length}) ` +
        'is invalid.');
    }
    M = M / octet_scalar_length;
  }

  /* Algorithm:

  1.  generators = BBS.create_generators(L + 1, api_id)
  2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  3.  commit = deserialize_and_validate_commit(
                 commitment_with_proof, blind_generators, api_id)
  4.  if commit is INVALID, return INVALID
  5.  (msg_1, ..., msg_L) = BBS.messages_to_scalars(messages, api_id)
  6.  res = B_calculate_with_nym(
              generators, commit, blind_generators[-1], messages)
  7.  if res is INVALID, return INVALID
  8.  (B) = res
  9.  blind_sig = FinalizeBlindSign(
                    SK, PK, B, generators, blind_generators, header, api_id)
  10. if blind_sig is INVALID, return INVALID
  11. return blind_sig

  */
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1, api_id: prependBlindApiId({api_id}), ciphersuite
  });
  const commitment = deserialize_and_validate_commit({
    commitment_with_proof, blind_generators, api_id, ciphersuite
  });
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const {B} = B_calculate_with_nym({
    generators, commitment,
    nym_generator: blind_generators.at(-1), signer_nym_entropy,
    message_scalars, ciphersuite
  });

  return FinalizeBlindSign({
    SK, PK, B, generators, blind_generators, header, api_id, ciphersuite
  });
}

export async function BlindVerifyWithNym({
  PK, signature, header, messages, committed_messages,
  prover_nym, signer_nym_entropy, secret_prover_blind = 0n,
  api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  assertArray(committed_messages, 'committed_messages');
  // FIXME: make any of these default to `0`?
  assertType('bigint', prover_nym, 'prover_nym');
  assertType('bigint', signer_nym_entropy, 'signer_nym_entropy');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Algorithm:

  1. nym_secret = prover_nym + signer_nym_entropy
  2. committed_messages.append(nym_secret)
  3. res = BlindBBS.Verify(PK, signature, header, messages,
                           committed_messages, secret_prover_blind, nym_secret)
  4. if res is INVALID, return INVALID
  5. return nym_secret

  */
  const {Fr} = ciphersuite;
  const nym_secret = Fr.add(prover_nym, signer_nym_entropy);
  const verified = await BlindVerify({
    PK, signature, header, messages,
    committed_messages,
    extra_committed_message_scalars: [nym_secret],
    secret_prover_blind, api_id, ciphersuite
  });
  return {verified, nym_secret};
}

// FIXME: perhaps remove this function if no longer used/specified in BBS spec
export function CalculatePseudonym({
  context_id, nym_secret, api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, context_id, 'context_id');
  assertType('bigint', nym_secret, 'nym_secret');
  ciphersuite = getCiphersuite(ciphersuite);
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');

  /* Algorithm:

  1. OP = hash_to_curve_g1(context_id, api_id)
  2. if OP is INVALID, return INVALID
  3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  4. return OP * nym_secret

  */
  const OP = ciphersuite.hash_to_curve_g1(context_id, api_id);
  // Identity_G1 == ciphersuite.Identity_E1
  const {BP1, Identity_E1, P1} = ciphersuite;
  if(OP.equals(Identity_E1) || OP.equals(BP1) || OP.equals(P1)) {
    throw new Error('Invalid context ID.');
  }
  // return point as bytes
  return ciphersuite.point_to_octets_E1(OP.multiply(nym_secret));
}

export async function NymCommit({
  prover_nym, committed_messages = [], api_id, ciphersuite,
  mocked_random_scalars_options
} = {}) {
  assertType('bigint', prover_nym, 'prover_nym');
  assertArray(committed_messages, 'committed_messages');
  ciphersuite = getCiphersuite(ciphersuite);

  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');

  /* Algorithm:

  1. committed_message_scalars = BBS.messages_to_scalars(
       committed_messages, api_id)
  2. committed_message_scalars.append(prover_nym)
  3. blind_generators = BBS.create_generators(
       length(committed_message_scalars) + 1, 'BLIND_' || api_id)
  4. return CoreCommit(committed_message_scalars, blind_generators, api_id)

  */
  const committed_message_scalars = messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  });
  committed_message_scalars.push(prover_nym);
  const blind_generators = create_generators({
    count: committed_message_scalars.length + 1,
    api_id: prependBlindApiId({api_id}), ciphersuite
  });
  return CoreCommit({
    committed_message_scalars, blind_generators,
    api_id, ciphersuite, mocked_random_scalars_options
  });
}

export async function ProofGenWithPseudonym({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  // the two extra "with pseudonym" params
  nym_secret, context_id,
  messages = [], disclosed_indexes = [],
  committed_messages = [], disclosed_committed_indexes = [],
  secret_prover_blind = 0n,
  api_id, ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  /* Note: The implementation from `BlindProofGen` is used below where the only
  changes are appending `nym_secret` to `committed_message_scalars` as an
  undisclosed, committed message and calling `CoreProofGenWithPseudonym`
  instead of `CoreProofGen`. The `BlindProofGen` function should be refactored
  in the future to better reuse code. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertType('bigint', nym_secret, 'nym_secret');
  assertInstance(Uint8Array, context_id, 'context_id');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  assertArray(committed_messages, 'committed_messages');
  assertArray(disclosed_committed_indexes, 'disclosed_committed_indexes');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. L = length(messages)
  2. M = length(committed_messages)
  3. if length(disclosed_indexes) > L, return INVALID
  4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
  5. if length(disclosed_committed_indexes) > M, return INVALID
  6. for j in disclosed_committed_indexes, if i < 0 or i >= M, return INVALID

  */
  const L = messages.length;
  const M = committed_messages.length;
  if(disclosed_indexes.length > L) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_indexes.length}) must be less ` +
      `than or equal to "messages.length" ${L}).`);
  }
  if(disclosed_indexes.some(i => i < 0 || i >= L)) {
    throw new Error(`Every disclosed index must be in the range [0, ${L}).`);
  }
  if(disclosed_committed_indexes.length > M) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_committed_indexes.length}) ` +
      `must be less than or equal to "committed_messages.length" ${M}).`);
  }
  if(disclosed_committed_indexes.some(i => i < 0 || i >= M)) {
    throw new Error(
      `Every disclosed commitment index must in the range [0, ${M}).`);
  }

  /* Algorithm:

  1.  message_scalars = BBS.messages_to_scalars(messages, api_id)
  2.  committed_message_scalars = ()
  3.  committed_message_scalars.append(secret_prover_blind)
  4.  committed_message_scalars.append(BBS.messages_to_scalars(
                                              committed_messages, api_id))
  5.  generators = BBS.create_generators(length(message_scalars) + 1, api_id)
  6.  blind_generators = BBS.create_generators(
                           length(committed_message_scalars) + 1,
                           "BLIND_" || api_id)
  7.  indexes = ()
  8.  indexes.append(disclosed_indexes)
  9.  for j in disclosed_committed_indexes: indexes.append(j + L + 1)
  10. proof = BBS.CoreProofGen(
                PK, signature, generators.append(blind_generators),
                header, ph, message_scalars.append(committed_message_scalars),
                indexes, api_id)
  11. return proof

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const committed_message_scalars = [
    secret_prover_blind,
    ...messages_to_scalars({messages: committed_messages, api_id, ciphersuite}),
    nym_secret
  ];
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: committed_message_scalars.length,
    api_id: prependBlindApiId({api_id}),
    ciphersuite
  });
  const indexes = disclosed_indexes.slice();
  for(const j of disclosed_committed_indexes) {
    indexes.push(j + L + 1);
  }
  return CoreProofGenWithPseudonym({
    PK, signature, context_id,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    messages: message_scalars.concat(committed_message_scalars),
    disclosed_indexes: indexes,
    api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
}

export function ProofVerifyWithPseudonym({
  PK, proof,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  // the two extra "with pseudonym" params
  pseudonym, context_id,
  L = 0,
  disclosed_messages,
  disclosed_committed_messages,
  disclosed_indexes,
  disclosed_committed_indexes,
  api_id, ciphersuite
} = {}) {
  /* Note: The only difference between `ProofVerifyWithPseudonym` and
  `BlindProofVerify` is the passing of the `pseudonym` and `verifier_id`
  parameters to `CoreProofVerifyWithPseudonym` instead of `CoreProofVerify`.
  This suggests `BlindProofVerify` could be better reused with some minor
  changes / parameterizing instead of duplicating its implementation here. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, pseudonym, 'pseudonym');
  assertInstance(Uint8Array, context_id, 'context_id');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertType('number', L, 'L');
  assertArray(disclosed_messages, 'disclosed_messages');
  assertArray(disclosed_committed_messages, 'disclosed_committed_messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  assertArray(disclosed_committed_indexes, 'disclosed_committed_indexes');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  // FIX to spec: Should be 3 * point length and 4 * octet length.
  // spec says `2 * octet_point_length + 3 * octet_scalar_length`
  1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  // FIX to spec: to spec add `- 1` for total number of messages
  4. total_no_messages = length(disclosed_indexes) +
                           length(disclosed_committed_indexes) + U - 1
  5. M = total_no_messages - L

  */
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
  const remainder = proof.length - proof_len_floor;
  if(remainder < 0) {
    throw new Error(
      `"proof.length" (${proof.length}) must be equal to or greater than ` +
      `${proof_len_floor}).`);
  }
  const U = Math.floor(remainder / octet_scalar_length);
  const total_no_messages = disclosed_indexes.length +
    disclosed_committed_indexes.length + U - 1;
  const M = total_no_messages - L;
  pseudonym = ciphersuite.octets_to_point_E1(pseudonym);

  /* Algorithm:

  1.  generators = BBS.create_generators(L + 1, api_id)
  2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  3.  disclosed_message_scalars = messages_to_scalars(
                                    disclosed_messages, api_id)
  4.  disclosed_committed_message_scalars =
        messages_to_scalars(disclosed_committed_messages, api_id)
  5.  message_scalars = disclosed_message_scalars.append(
                          disclosed_committed_message_scalars)
  6.  indexes = ()
  7.  indexes.append(disclosed_indexes)
  8.  for j in disclosed_committed_indexes: indexes.append(j + L + 1)
  9.  result = CoreProofVerifyWithPseudonym(
                 PK, proof, pseudonym, generators.append(blind_generators),
                 header, ph, message_scalars, indexes, api_id)
  10. return result

  */
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1,
    api_id: prependBlindApiId({api_id}),
    ciphersuite
  });
  const disclosed_message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const disclosed_committed_message_scalars = messages_to_scalars({
    messages: disclosed_committed_messages, api_id, ciphersuite
  });
  const message_scalars = disclosed_message_scalars
    .concat(disclosed_committed_message_scalars);
  const indexes = disclosed_indexes.slice();
  for(const j of disclosed_committed_indexes) {
    indexes.push(j + L + 1);
  }
  return CoreProofVerifyWithPseudonym({
    PK, proof, pseudonym, context_id,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    disclosed_messages: message_scalars,
    disclosed_indexes: indexes,
    api_id, ciphersuite
  });
}
