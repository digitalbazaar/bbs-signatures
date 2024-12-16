/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from '../../assert.js';
import {
  concatGenerators, create_generators, createApiId, messages_to_scalars
} from '../util.js';
import {
  CoreProofGenWithPseudonym,
  CoreProofVerifyWithPseudonym
} from './core.js';
import {B_calculate_with_nym} from './util.js';
import {BLIND_API_ID} from '../constants.js';
import {deserialize_and_validate_commit} from '../blind/commitment.js';
import {FinalizeBlindSign} from '../blind/core.js';
import {getCiphersuite} from '../ciphersuites.js';
import {prependBlindApiId} from '../blind/util.js';

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

// FIXME: continue from here
export function CalculatePseudonym({
  verifier_id, pid, api_id, ciphersuite
} = {}) {
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  ciphersuite = getCiphersuite(ciphersuite);
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
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
  if(OP.equals(Identity_E1) || OP.equals(BP1) || OP.equals(P1)) {
    throw new Error('Invalid verifier ID.');
  }
  const messages = [pid];
  const [pid_scalar] = messages_to_scalars({messages, api_id, ciphersuite});
  // return point as bytes
  return ciphersuite.point_to_octets_E1(OP.multiply(pid_scalar));
}

export async function HiddenPidProofGenWithPseudonym({
  PK, signature,
  // the three extra "with pseudonym" params
  pseudonym, verifier_id, pid,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  secret_prover_blind = 0n,
  signer_blind = 0n,
  api_id, ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  /* Note: `HiddenPidProofGenWithPseudonym` could be implemented by calling
  `BlindProofGen` with `pid` as the only committed message if `BlindProofGen`
  also accepted additional `init_res` values, i.e., those used in
  `pseudonym_init_res`, which is generated by `CoreProofGenWithPseudonym`. There
  are no other differences. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, pseudonym, 'pseudonym');
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  assertType('bigint', secret_prover_blind, 'secret_prover_blind');
  assertType('bigint', signer_blind, 'signer_blind');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. L = length(messages)
  2. if length(disclosed_indexes) > L, return INVALID
  3. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
  // FIX to spec: no `disclosed_commitment_indexes`
  4. for j in disclosed_commitment_indexes, if i < 0 or i >= L, return INVALID

  */
  const L = messages.length;
  // there is one committed message, `pid`; there are no
  // disclosed_commitment_indexes
  const committed_messages = [pid];
  const disclosed_commitment_indexes = [];
  const M = committed_messages.length;
  if(disclosed_indexes.length > L) {
    throw new Error(
      `"disclosed_indexes.length" (${disclosed_indexes.length}) must be less ` +
      `than or equal to "messages.length" ${L}).`);
  }
  if(disclosed_indexes.some(i => i < 0 || i >= L)) {
    throw new Error(`Every disclosed index must be in the range [0, ${L}).`);
  }

  // validate pseudonym is a valid E1 (G1) point
  pseudonym = ciphersuite.octets_to_point_E1(pseudonym);

  /* Algorithm:

  Note: The steps from `BlindProofGen` are used here where the only change
  is calling `CoreProofGenWithPseudonym` instead of `CoreProofGen`. This
  should allow a future refactor that better shares code.

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
  11. proof = CoreProofGenWithPseudonym(
                PK, signature,
                pseudonym, verifier_id,
                generators.append(blind_generators), header, ph,
                message_scalars.append(committed_message_scalars),
                disclosed_indexes, api_id)
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
  return CoreProofGenWithPseudonym({
    PK, signature,
    pseudonym, verifier_id,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    messages: message_scalars.concat(committed_message_scalars),
    disclosed_indexes: indexes,
    api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
}

export async function ProofGenWithPseudonym({
  PK, signature,
  // the three extra "with pseudonym" params
  pseudonym, verifier_id, pid,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes = [],
  api_id, ciphersuite,
  // for test suite only
  mocked_random_scalars_options
} = {}) {
  /* Note: The only difference between `ProofGenWithPseudonym` and `ProofGen`
  is the appending of `pid` to `messages` and the passing of `pseudonym`,
  `verifier_id`, `pid_scalar` to `CoreProofGenWithPseudonym` instead of
  `CoreProofGen`. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, pseudonym, 'pseudonym');
  assertInstance(Uint8Array, verifier_id, 'verifier_id');
  assertInstance(Uint8Array, pid, 'pid');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, ph, 'ph');
  assertArray(messages, 'messages');
  assertArray(disclosed_indexes, 'disclosed_indexes');
  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  // validate pseudonym is a valid E1 (G1) point
  pseudonym = ciphersuite.octets_to_point_E1(pseudonym);

  /* Algorithm:

  1. messages.append(pid) // add pid to end of messages
  2. message_scalars = messages_to_scalars(messages, api_id)
  // FIX to spec: unnecessary duplicate computation of `pid_scalar`
  3. pid_scalar = messages_to_scalars((pid), api_id)
  4. generators = create_generators(length(messages) + 1, api_id)
  // FIX to spec: always include a blind generator for the pseudonym
  5. blind_generators = BBS.create_generators(1, "BLIND_" || api_id)
  6. proof = CoreProofGenWithPseudonym(
               PK, signature, pseudonym, verifier_id,
               generators.append(blind_generators),
               header, ph, message_scalars, disclosed_indexes, api_id)
  7. if proof is INVALID, return INVALID
  8. return proof

  */
  messages = [...messages, pid];
  const message_scalars = messages_to_scalars({messages, api_id, ciphersuite});
  const generators = create_generators({
    count: messages.length + 1, api_id, ciphersuite
  });
  const blind_generators = create_generators({
    count: 1,
    api_id: prependBlindApiId({api_id}),
    ciphersuite
  });
  // FIXME: determine if this should be done
  // add `0` blind factor to message scalars as blind sign was used with
  // an empty `commitment_with_message`
  message_scalars.push(0n);
  return CoreProofGenWithPseudonym({
    PK, signature,
    pseudonym, verifier_id,
    generators: concatGenerators(generators, blind_generators),
    header, ph,
    messages: message_scalars, disclosed_indexes, api_id, ciphersuite,
    // for test suite only
    mocked_random_scalars_options
  });
}

export async function ProofVerifyWithPseudonym({
  PK, proof,
  // the total number of signer provided messages in the original signature:
  L,
  // the two extra "with pseudonym" params
  pseudonym, verifier_id,
  header, ph, disclosed_messages, disclosed_indexes,
  api_id, ciphersuite
} = {}) {
  /* Note: The only difference between `ProofVerifyWithPseudonym` and
  `ProofVerify` is the passing of the `Pseudonym` and `verifier_id` parameters
  to `CoreProofVerifyWithPseudonym` instead of `CoreProofVerify`. */

  assertInstance(Uint8Array, PK, 'PK');
  assertInstance(Uint8Array, proof, 'proof');
  assertType('number', L, 'L');
  assertInstance(Uint8Array, pseudonym, 'pseudonym');
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
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');
  ciphersuite = getCiphersuite(ciphersuite);

  /* Deserialization:

  1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  2. if length(proof) < proof_len_floor, return INVALID
  3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  // FIX to spec: `disclosed_committed_indexes` does not exist, current
  // implementation uses `0` for its length
  4. total_no_messages = length(disclosed_indexes) +
       length(disclosed_committed_indexes) + U - 1
  5. M = total_no_messages - L
  6. R = length(disclosed_indexes)

  */
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
  // note: M is set to a minimum of zero, see algorithm below for why.
  const M = Math.max(0, total_no_messages - L);
  //const M = total_no_messages - L;
  pseudonym = ciphersuite.octets_to_point_E1(pseudonym);

  /* Algorithm:

  1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  2. generators = create_generators(L + 1, api_id)
  // FIX to spec: since BlindSign *always* creates at least one blind
  // generator, we must do the same here, forcing M to be 0 if it is less
  // than 1
  //3. blind_generators = []
  //4. if M > -1, blind_generators = create_generators(M + 1, "BLIND_" + api_id)
  3. if M < 0, M = 0 (FIXME: should be an error if M < 0)
  4. blind_generators = create_generators(M + 1, "BLIND_" + api_id)
  5. result = CoreProofVerifyWithPseudonym(
                PK, proof,
                pseudonym, verifier_id,
                generators.append(blind_generators),
                header, ph,
                message_scalars, disclosed_indexes, api_id)
  6. return result

  */
  const message_scalars = messages_to_scalars({
    messages: disclosed_messages, api_id, ciphersuite
  });
  const generators = create_generators({count: L + 1, api_id, ciphersuite});
  let blind_generators;
  // FIXME: less than `0` will be an error if pseudonym always uses a blind
  // factor
  if(M > -1) {
    blind_generators = create_generators({
      count: M + 1,
      api_id: prependBlindApiId({api_id}),
      ciphersuite
    });
  } else {
    blind_generators = [];
  }
  return CoreProofVerifyWithPseudonym({
    PK, proof,
    pseudonym, verifier_id,
    //generators: concatGenerators(generators, blind_generators),
    generators,
    blind_generators,
    header, ph,
    disclosed_messages: message_scalars, disclosed_indexes,
    api_id, ciphersuite
  });
}
