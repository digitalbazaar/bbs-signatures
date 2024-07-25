/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../../assert.js';
import {
  concatGenerators, create_generators, createApiId, messages_to_scalars
} from '../util.js';
import {CoreProofGen, CoreProofVerify, CoreVerify} from '../core.js';
import {get_disclosed_data, prependBlindApiId} from './util.js';
import {BLIND_API_ID} from '../constants.js';
import {CoreBlindSign} from './core.js';
import {getCiphersuite} from '../ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export {Commit} from './commitment.js';

export async function BlindSign({
  SK, PK,
  commitment_with_proof = new Uint8Array(),
  header = new Uint8Array(), messages = [],
  signer_blind = 0n, ciphersuite
} = {}) {
  assertType('bigint', SK, 'SK');
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

  /* Deserialization:

  1. L = length(messages)
  // calculate the number of blind generators used by the commitment,
  // if any.
  2. M = length(commitment_with_proof)
  // FIXME: to spec, should say `2 * octet_scalar_length`, does not
  // multiply by `2` in draft 6, corrected below in step 3:
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

  1. generators = BBS.create_generators(L + 1, api_id)
  2. blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)

  3. message_scalars = BBS.messages_to_scalars(messages, api_id)
  4. blind_sig = CoreBlindSign(
                   SK, PK, commitment_with_proof,
                   generators, blind_generators,
                   header, message_scalars, signer_blind, api_id)
  5. if blind_sig is INVALID, return INVALID
  6. return blind_sig

  */
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1, api_id: prependBlindApiId({api_id}), ciphersuite
  });
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const signature = CoreBlindSign({
    SK, PK, commitment_with_proof,
    generators, blind_generators,
    header, message_scalars, signer_blind,
    api_id, ciphersuite
  });
  return signature;
}

export async function BlindProofGen({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  committed_messages = [], disclosed_commitment_indexes = [],
  secret_prover_blind = 0n,
  signer_blind = 0n,
  ciphersuite,
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
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

  /* Algorithm:

  1.  message_scalars = ()
  2.  if secret_prover_blind != 0, message_scalars.append(
                                      secret_prover_blind + signer_blind)

  4.  message_scalars.append(BBS.messages_to_scalars(
                               committed_messages, api_id))
  5.  message_scalars.append(BBS.messages_to_scalars(messages, api_id))

  6.  generators = BBS.create_generators(length(message_scalars) + 1,
                                         "BLIND_" || api_id)
  7.  disclosed_data = get_disclosed_data(
                                    messages,
                                    committed_messages,
                                    disclosed_indexes,
                                    disclosed_commitment_indexes,
                                    secret_prover_blind)
  8.  if disclosed_data is INVALID, return INVALID.
  9.  (disclosed_msgs, disclosed_idxs) = disclosed_data

  10. proof = BBS.CoreProofGen(PK, signature, generators, header, ph,
                                  message_scalars, disclosed_idxs, api_id)
  11. return (proof, disclosed_msgs, disclosed_idxs)

  */
  const message_scalars = [];
  if(secret_prover_blind !== 0n) {
    const {Fr} = ciphersuite;
    message_scalars.push(Fr.add(secret_prover_blind, signer_blind));
  }
  message_scalars.push(...messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  }));
  message_scalars.push(...messages_to_scalars({messages, api_id, ciphersuite}));
  const generators = create_generators({
    count: message_scalars.length + 1,
    api_id: prependBlindApiId({api_id}),
    ciphersuite
  });
  const disclosed_data = get_disclosed_data({
    messages, disclosed_indexes,
    committed_messages, disclosed_commitment_indexes,
    secret_prover_blind
  });
  const proof = await CoreProofGen({
    PK, signature, generators, header, ph,
    messages: message_scalars,
    disclosed_indexes: disclosed_data.disclosed_indexes,
    api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
  return {proof, ...disclosed_data};
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
  ciphersuite
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
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

  /* Deserialization:

  1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  4. total_no_messages = length(disclosed_indexes) +
                              length(disclosed_committed_indexes) + U - 1
  5. M = total_no_messages - L

  */
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  const proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length;
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
  signer_blind = 0n,
  ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  assertArray(committed_messages, 'committed_messages');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  assertType('bigint', signer_blind, 'signer_blind');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

  /* Deserialization:

  1. L = length(messages)
  2. M = length(committed_messages)

  */
  const L = messages.length;
  const M = committed_messages.length;

  /* Algorithm:

  1. generators = BBS.create_generators(L + 1, api_id)
  // FIX to spec: spec needs to say that the number of blind generators should
  // be zero when `secret_prover_blind === 0n`
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
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});

  const committed_message_scalars = [];
  // FIX to spec: spec needs to be explicit about this code branching based on
  // `secret_prover_blind`
  let blind_generators;
  if(secret_prover_blind !== 0n) {
    const {Fr} = ciphersuite;
    const blind_factor = Fr.add(secret_prover_blind, signer_blind);
    committed_message_scalars.push(blind_factor);
    blind_generators = create_generators({
      count: M + 1, api_id: prependBlindApiId({api_id}), ciphersuite
    });
  } else {
    blind_generators = [];
  }
  committed_message_scalars.push(...messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  }));

  const result = CoreVerify({
    PK, signature,
    generators: concatGenerators(generators, blind_generators),
    header,
    messages: message_scalars.concat(committed_message_scalars),
    api_id, ciphersuite
  });
  return result;
}
