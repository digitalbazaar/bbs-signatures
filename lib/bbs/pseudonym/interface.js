/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance} from '../../assert.js';
import {
  concatGenerators, create_generators, createApiId, messages_to_scalars
} from '../util.js';
import {
  CoreProofGenWithPseudonym,
  CoreProofVerifyWithPseudonym
} from './core.js';
import {getCiphersuite} from '../ciphersuites.js';
import {prependBlindApiId} from '../blind/util.js';
import {PSEUDONYM_API_ID} from '../constants.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function CalculatePseudonym({
  verifier_id, pid, api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  ciphersuite = getCiphersuite(ciphersuite);
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');

  /* Algorithm:

  1. OP = hash_to_curve_g1(verifier_id, api_id)
  2. if OP is INVALID, return INVALID
  3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  3. pid_scalar = messages_to_scalars((pid), api_id)
  4. return OP * pid_scalar

  */
  const OP = ciphersuite.hash_to_curve_g1(verifier_id, api_id);
  // Identity_G1 == ciphersuite.Identity_E1
  const {BP1, Identity_E1, P1} = ciphersuite;
  if(OP.equals(Identity_E1) || OP.equals(BP1) || OP.equals(OP, P1)) {
    throw new Error('Invalid verifier ID.');
  }
  const messages = [pid];
  const pid_scalar = messages_to_scalars({messages, api_id, ciphersuite});
  return OP.multiply(pid_scalar);
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
  /* Note: The only difference between `ProofGenWithPseudonym` and `ProofGen`
  is the appending of `pid` to `messages` and the passing of `Pseudonym`,
  `verifier_id`, `pid_scalar` to `CoreProofGenWithPseudonym` instead of
  `CoreProofGen`. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, Pseudonym, 'Pseudonym');
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  ciphersuite = getCiphersuite(ciphersuite);

  const api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);

  // validate pseudonym is a valid E1 (G1) point
  Pseudonym = ciphersuite.octets_to_point_E1(Pseudonym);

  /* Algorithm:

  1. messages.append(pid) // add pid to end of messages
  2. message_scalars = messages_to_scalars(messages, api_id)
  // FIX to spec: unnecessary duplicate computation of `pid_scalar`
  3. pid_scalar = messages_to_scalars((pid), api_id)
  4. generators = create_generators(length(messages) + 1, api_id)
  5. proof = CoreProofGenWithPseudonym(
               PK, signature, Pseudonym, verifier_id, generators,
               header, ph, message_scalars, disclosed_indexes, api_id)
  6. if proof is INVALID, return INVALID
  7. return proof

  */
  messages = messages.slice();
  messages.push(pid);
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const proof = await CoreProofGenWithPseudonym({
    PK, signature,
    Pseudonym, verifier_id,
    generators, header, ph,
    messages: message_scalars, disclosed_indexes, api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
  return proof;
}

export async function ProofVerifyWithPseudonym({
  PK, proof,
  // the total number of signer provided messages in the original signature:
  L,
  // the two extra "with pseudonym" params
  Pseudonym_octets, verifier_id,
  header, ph, disclosed_messages, disclosed_indexes,
  api_id, ciphersuite
} = {}) {
  /* Note: The only difference between `ProofVerifyWithPseudonym` and
  `ProofVerify` is the deserialization of `Pseudonym_octets` to `Pseudonym`
  and the passing of it and `verifier_id` to `CoreProofVerifyWithPseudonym`
  instead of `CoreProofVerify`. */

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
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, PSEUDONYM_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  // FIX to spec: `disclosed_committed_indexes` does not exist, current
  // implementatino uses `0` for its length
  4. total_no_messages = length(disclosed_indexes) +
       length(disclosed_committed_indexes) + U - 1
  5. M = total_no_messages - L
  6. R = length(disclosed_indexes)

  */
  // note: `proof_len_floor` is checked in `CoreProofVerify`
  const {octet_point_length, octet_scalar_length} = ciphersuite;
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
  const total_no_messages = R + U - 1;
  const M = total_no_messages - L;
  const Pseudonym = ciphersuite.octets_to_point_E1(Pseudonym_octets);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  2. generators = create_generators(L + 1, api_id)
  3. blind_generators = create_generators(M + 1, "BLIND_" + api_id)
  4. result = CoreProofVerifyWithPseudonym(
                PK, proof,
                Pseudonym, verifier_id,
                generators.append(blind_generators),
                header, ph,
                message_scalars, disclosed_indexes, api_id)
  4. return result

  */
  const message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  const blind_generators = create_generators({
    count: M + 1,
    api_id: prependBlindApiId({api_id}),
    ciphersuite
  });
  return CoreProofVerifyWithPseudonym({
    PK, proof,
    Pseudonym, verifier_id,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    disclosed_messages: message_scalars, disclosed_indexes,
    api_id, ciphersuite
  });
}
