/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../assert.js';
import {
  CoreBlindSign,
  CoreProofGen, CoreProofGenWithPseudonym,
  CoreProofVerify, CoreProofVerifyWithPseudonym,
  CoreSign, CoreVerify
} from './core.js';
import {
  create_generators,
  get_disclosed_data,
  messages_to_scalars,
  TEXT_ENCODER
} from './util.js';
import {CalculatePseudonym as _CalculatePseudonym} from './pseudonym.js';
import {getCiphersuite} from './ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

const BLIND_API_ID = 'BLIND_H2G_HM2S_';
const CORE_API_ID = 'H2G_HM2S_';
const PSEUDONYM_API_ID = 'H2G_HM2S_PSEUDONYM_';

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

  const api_id = _createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

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
    if(M < 0 || (M % octet_point_length !== 0)) {
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

  const api_id = _createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);

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
    message_scalars.push(secret_prover_blind + signer_blind);
  }
  message_scalars.push(...messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  }));
  message_scalars.push(...messages_to_scalars({messages, api_id, ciphersuite}));
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
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

export function CalculatePseudonym({verifier_id, pid, ciphersuite} = {}) {
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  ciphersuite = getCiphersuite(ciphersuite);
  const api_id = _createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  return _CalculatePseudonym({verifier_id, pid, api_id, ciphersuite});
}

export async function ProofGen({
  PK, signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
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
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id, CORE_API_ID);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. proof = CoreProofGen(PK, signature, generators, header, ph,
                          message_scalars, disclosed_indexes, api_id)
  4. if proof is INVALID, return INVALID
  5. return proof

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const proof = await CoreProofGen({
    PK, signature, generators, header, ph,
    messages: message_scalars, disclosed_indexes, api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
  return proof;
}

export async function ProofGenWithPseudonym({
  PK, signature,
  // the three extra "with pseudonym" params
  Pseudonym, verifier_id, pid,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  /* Note: The only difference between this and `ProofGen` is the creation of
  an additional generator, the creation of `pid_scalar` and the passing of
  `Pseudonym`, `verifier_id`, `pid_scalar` to `CoreProofGenWithPseudonym`
  instead of `CoreProofGen`. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. pid_scalar = messages_to_scalars((pid), api_id)
  3. generators = create_generators(length(messages) + 2, PK, api_id)
  4. proof = CoreProofGenWithPseudonym(
              PK, signature, Pseudonym, verifier_id, pid_scalar, generators,
              header, ph, message_scalars, disclosed_indexes, api_id)
  5. if proof is INVALID, return INVALID
  6. return proof

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const pid_scalar = messages_to_scalars({
    messages: [pid], api_id, ciphersuite
  });
  const generators = create_generators({
    count: messages.length + 2, api_id, ciphersuite
  });
  const proof = await CoreProofGenWithPseudonym({
    PK, signature,
    Pseudonym, verifier_id, pid_scalar,
    generators, header, ph,
    messages: message_scalars, disclosed_indexes, api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
  return proof;
}

export async function ProofVerify({
  PK, proof, header, ph, disclosed_messages, disclosed_indexes, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(disclosed_messages, 'disclosed_messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  if(disclosed_messages.length !== disclosed_indexes.length) {
    throw new Error(
      `"disclosed_messages.length" (${disclosed_messages.length}) must ` +
      `equal "disclosed_indexes.length" (${disclosed_indexes.length}).`);
  }
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id, CORE_API_ID);

  /* Deserialization:

  1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  4. R = length(disclosed_indexes)

  */
  // note: `proof_len_floor` is checked in `CoreProofVerify`
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  // FIX to spec: Should be 3 * point length and 4 * octet length.
  const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
  if(proof.length < proof_len_floor) {
    throw new Error(
      `"proof.length" (${proof.length}) ` +
      `must be at least ${proof_len_floor}.`);
  }
  // check total proof size is valid
  const remainder = proof.length - proof_len_floor;
  if(remainder % octet_scalar_length !== 0) {
    throw new Error('Invalid proof size.');
  }
  const U = remainder / octet_scalar_length;
  const R = disclosed_indexes.length;

  /* Algorithm:

  1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  2. generators = create_generators(U + R + 1, api_id)
  3. result = CoreProofVerify(PK, proof, generators, header, ph,
                              message_scalars, disclosed_indexes, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const generators = create_generators({count: U + R + 1, api_id, ciphersuite});
  const result = CoreProofVerify({
    PK, proof, generators, header, ph,
    disclosed_messages: message_scalars, disclosed_indexes,
    api_id, ciphersuite
  });
  return result;
}

export async function ProofVerifyWithPseudonym({
  PK, proof,
  // the two extra "with pseudonym" params
  Pseudonym_octets, verifier_id,
  header, ph, disclosed_messages, disclosed_indexes, ciphersuite
} = {}) {
  /* Note: The only difference between this and `ProofVerify` is the
  deserialization of `Pseudonym_octets` to `Pseudonym` and the passing of
  it and `verifier_id` to `CoreProofVerifyWithPseudonym` instead of
  `CoreProofVerify`. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, Pseudonym_octets, 'Pseudonym_octets');
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(disclosed_messages, 'disclosed_messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  if(disclosed_messages.length !== disclosed_indexes.length) {
    throw new Error(
      `"disclosed_messages.length" (${disclosed_messages.length}) must ` +
      `equal "disclosed_indexes.length" (${disclosed_indexes.length}).`);
  }
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);

  /* Deserialization:

  1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  4. R = length(disclosed_indexes)
  5. Pseudonym = octets_to_point_E1(PseudonymOctets)

  */
  // note: `proof_len_floor` is checked in `CoreProofVerify`
  const {octet_point_length, octet_scalar_length} = ciphersuite;
  // FIX to spec: Should be 3 * point length and 4 * octet length.
  const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
  if(proof.length < proof_len_floor) {
    throw new Error(
      `"proof.length" (${proof.length}) ` +
      `must be at least ${proof_len_floor}.`);
  }
  // check total proof size is valid
  const remainder = proof.length - proof_len_floor;
  if(remainder % octet_scalar_length !== 0) {
    throw new Error('Invalid proof size.');
  }
  const U = remainder / octet_scalar_length;
  const R = disclosed_indexes.length;
  const Pseudonym = ciphersuite.octets_to_point_E1(Pseudonym_octets);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  2. generators = create_generators(U + R + 1, api_id)
  3. result = CoreProofVerifyWithPseudonym(
                PK, proof,
                Pseudonym, verifier_id,
                generators, header, ph,
                message_scalars, disclosed_indexes, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const generators = create_generators({count: U + R + 1, api_id, ciphersuite});
  const result = CoreProofVerifyWithPseudonym({
    PK, proof,
    Pseudonym, verifier_id,
    generators, header, ph,
    disclosed_messages: message_scalars, disclosed_indexes,
    api_id, ciphersuite
  });
  return result;
}

export async function Sign({
  SK, PK, header = new Uint8Array(), messages = [], pid, ciphersuite
} = {}) {
  assertType('bigint', SK, 'SK');
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  if(pid !== undefined) {
    assertInstance(Uint8Array, pid, 'pid');
    // always push `pid` onto end of messages
    messages = messages.slice();
    messages.push(pid);
  }
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(
    ciphersuite.ciphersuite_id, pid ? PSEUDONYM_API_ID : CORE_API_ID);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. signature = CoreSign(SK, PK, generators, header, message_scalars, api_id)
  4. if signature is INVALID, return INVALID
  5. return signature

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const signature = CoreSign({
    SK, PK, generators, header, messages: message_scalars, api_id, ciphersuite
  });
  return signature;
}

export async function Verify({
  PK, signature, header, messages, pid, ciphersuite
} = {}) {
  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  if(pid !== undefined) {
    assertInstance(Uint8Array, pid, 'pid');
    // always push `pid` onto end of messages
    messages = messages.slice();
    messages.push(pid);
  }
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = _createApiId(
    ciphersuite.ciphersuite_id, pid ? PSEUDONYM_API_ID : CORE_API_ID);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(messages, api_id)
  2. generators = create_generators(length(messages)+1, api_id)
  3. result = CoreVerify(PK, signature, generators, header,
                         message_scalars, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const result = CoreVerify({
    PK, signature, generators, header, messages: message_scalars,
    api_id, ciphersuite
  });
  return result;
}

function _createApiId(ciphersuite_id, suffix) {
  return TEXT_ENCODER.encode(ciphersuite_id + suffix);
}
