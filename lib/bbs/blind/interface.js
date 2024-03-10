/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../../assert.js';
import {CoreProofGen, CoreVerify} from '../core.js';
import {create_generators, createApiId, messages_to_scalars} from '../util.js';
import {BLIND_API_ID} from '../constants.js';
import {CoreBlindSign} from './core.js';
import {get_disclosed_data} from './util.js';
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
  3. if M != 0, M = M - octet_point_length - octet_scalar_length
  4. M = M / octet_scalar_length
  5. if M < 0, return INVALID

  */
  const L = messages.length;
  let M = commitment_with_proof.length;
  if(M !== 0) {
    const {octet_point_length, octet_scalar_length} = ciphersuite;
    M = M - octet_point_length - octet_scalar_length;
    if(M < 0 || (M % octet_scalar_length !== 0)) {
      throw new Error(
        `"commitment_with_proof.length" (${commitment_with_proof.length}) ` +
        'is invalid.');
    }
    M = M / octet_scalar_length;
  }

  /* Algorithm:

  1. message_scalars = BBS.messages_to_scalars(messages, api_id)
  2. generators = BBS.create_generators(M + L + 1, api_id)
  3. blind_sig = CoreBlindSign(
                   SK, PK, commitment_with_proof, generators,
                   header, message_scalars, signer_blind, api_id)
  4. if blind_sig is INVALID, return INVALID
  5. return blind_sig

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: M + L + 1, api_id, ciphersuite
  });
  const signature = CoreBlindSign({
    SK, PK, commitment_with_proof,
    generators, header, messages: message_scalars, signer_blind,
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
                                                                  api_id)
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
    count: message_scalars.length + 1, api_id, ciphersuite
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

  /* Algorithm:

  1. message_scalars = ()
  2. if secret_prover_blind != 0,
       message_scalars.append(secret_prover_blind + signer_blind)
  3. message_scalars.append(
       BBS.messages_to_scalars(committed_messages, api_id))
  4. message_scalars.append(BBS.messages_to_scalars(messages, api_id))
  5. generators = BBS.create_generators(
                    length(message_scalars) + 1, api_id)
  6. res = BBS.CoreVerify(
             PK, signature, generators, header, messages, api_id)
  7. return res

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
    count: message_scalars.length + 1, api_id, ciphersuite
  });
  const result = CoreVerify({
    PK, signature, generators, header, messages: message_scalars,
    api_id, ciphersuite
  });
  return result;
}
