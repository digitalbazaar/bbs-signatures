/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../../assert.js';
import {blind_B_calculate, prependBlindApiId} from './util.js';
import {
  concatGenerators, create_generators, createApiId, messages_to_scalars
} from '../util.js';
import {CoreProofGen, CoreProofVerify, CoreVerify} from '../core.js';
import {BLIND_API_ID} from '../constants.js';
import {deserialize_and_validate_commit} from './commitment.js';
import {FinalizeBlindSign} from './core.js';
import {getCiphersuite} from '../ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export {commit as Commit} from './commitment.js';

export async function BlindSign({
  SK, PK,
  commitment_with_proof = new Uint8Array(),
  header = new Uint8Array(), messages = [],
  api_id, ciphersuite
} = {}) {
  assertType('bigint', SK, 'SK');
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
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
  2.  blind_generators = BBS.create_generators(M, "BLIND_" || api_id)
  3.  commit = deserialize_and_validate_commit(commitment_with_proof,
                                                blind_generators, api_id)
  4.  if commit is INVALID, return INVALID
  5.  (msg_1, ..., msg_L) = BBS.messages_to_scalars(messages, api_id)
  6.  res = B_calculate(generators, commit, messages)
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
  const {B} = blind_B_calculate({
    generators, commitment, message_scalars, ciphersuite
  });

  return FinalizeBlindSign({
    SK, PK, B, generators, blind_generators, header, api_id, ciphersuite
  });
}

export async function BlindProofGen({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  committed_messages = [], disclosed_commitment_indexes = [],
  secret_prover_blind = 0n,
  // FIXME: remove `signer_blind`
  signer_blind = 0n,
  api_id, ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  assertArray(committed_messages, 'committed_messages');
  assertArray(disclosed_commitment_indexes, 'disclosed_commitment_indexes');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  assertType('bigint', signer_blind, 'signer_blind');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. L = length(messages)
  2. M = length(committed_messages)
  3. if length(disclosed_indexes) > L, return INVALID
  4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
  5. if length(disclosed_commitment_indexes) > M, return INVALID
  6. for j in disclosed_commitment_indexes,
                                if i < 0 or i >= M, return INVALID
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
  if(disclosed_commitment_indexes.length > M) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_commitment_indexes.length}) ` +
      `must be less than or equal to "committed_messages.length" ${M}).`);
  }
  if(disclosed_commitment_indexes.some(i => i < 0 || i >= M)) {
    throw new Error(
      `Every disclosed commitment index must in the range [0, ${M}).`);
  }

  /* Algorithm:

  1.  generators = BBS.create_generators(L + 1, api_id)
  2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  3.  message_scalars = BBS.messages_to_scalars(messages, api_id)
  4.  committed_message_scalars = ()
  5.  blind_factor = secret_prover_blind + signer_blind
  6.  committed_message_scalars.append(blind_factor)
  7.  committed_message_scalars.append(BBS.messages_to_scalars(
                                        committed_messages, api_id))
  8.  indexes = ()
  9.  indexes.append(disclosed_indexes)
  10. for j in disclosed_commitment_indexes: indexes.append(j + L + 1)
  11. proof = BBS.CoreProofGen(
                PK, signature, generators.append(blind_generators),
                header, ph, message_scalars.append(committed_message_scalars),
                indexes, api_id)
  12. return proof

  */
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1, api_id: prependBlindApiId({api_id}), ciphersuite
  });
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const {Fr} = ciphersuite;
  const blind_factor = secret_prover_blind === 0n ?
    Fr.create(signer_blind) : Fr.add(secret_prover_blind, signer_blind);
  const committed_message_scalars = [
    blind_factor,
    ...messages_to_scalars({messages: committed_messages, api_id, ciphersuite})
  ];
  const indexes = disclosed_indexes.slice();
  for(const j of disclosed_commitment_indexes) {
    indexes.push(j + L + 1);
  }
  return CoreProofGen({
    PK, signature,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    messages: message_scalars.concat(committed_message_scalars),
    disclosed_indexes: indexes,
    api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
}

export async function BlindProofVerify({
  PK, proof,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  L = 0,
  disclosed_messages,
  disclosed_committed_messages,
  disclosed_indexes,
  disclosed_committed_indexes,
  api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertType('number', L, 'L');
  assertArray(disclosed_messages, 'disclosed_messages');
  assertArray(disclosed_committed_messages, 'disclosed_committed_messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  assertArray(disclosed_committed_indexes, 'disclosed_committed_indexes');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  // FIX to spec: Should be 3 * point length and 4 * octet length.
  // spec says `2 * octet_point_length + 3 * octet_scalar_length`
  1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
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
  8.  for j in disclosed_commitment_indexes: indexes.append(j + L + 1)
  9.  result = BBS.CoreProofVerify(
                 PK, proof, generators.append(blind_generators),
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
  return CoreProofVerify({
    PK, proof, generators: concatGenerators(generators, blind_generators),
    header, ph,
    disclosed_messages: message_scalars,
    disclosed_indexes: indexes,
    api_id, ciphersuite
  });
}

export async function BlindVerify({
  PK, signature, header,
  messages, committed_messages,
  secret_prover_blind = 0n,
  // FIXME: remove `signer_blind`
  signer_blind = 0n,
  api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  assertArray(committed_messages, 'committed_messages');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  assertType('bigint', signer_blind, 'signer_blind');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. L = length(messages)
  2. M = length(committed_messages)

  */
  const L = messages.length;
  const M = committed_messages.length;

  /* Algorithm:

  1. generators = BBS.create_generators(L + 1, api_id)
  2. blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  3. message_scalars = BBS.messages_to_scalars(messages, api_id)
  4. committed_message_scalars = ()
  5. blind_factor = secret_prover_blind + signer_blind
  6. committed_message_scalars.append(blind_factor)
  7. committed_message_scalars.append(BBS.messages_to_scalars(
                                      committed_messages, api_id))
  8. res = BBS.CoreVerify(
             PK, signature, generators.append(blind_generators),
             header, message_scalars.append(committed_message_scalars), api_id)
  9. return res

  */
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1, api_id: prependBlindApiId({api_id}), ciphersuite
  });
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const {Fr} = ciphersuite;
  const blind_factor = secret_prover_blind === 0n ?
    Fr.create(signer_blind) : Fr.add(secret_prover_blind, signer_blind);
  const committed_message_scalars = [
    blind_factor,
    ...messages_to_scalars({messages: committed_messages, api_id, ciphersuite})
  ];
  return CoreVerify({
    PK, signature,
    generators: concatGenerators(generators, blind_generators),
    header,
    messages: message_scalars.concat(committed_message_scalars),
    api_id, ciphersuite
  });
}
