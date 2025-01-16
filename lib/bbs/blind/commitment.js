/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance} from '../../assert.js';
import {CoreCommit, CoreCommitVerify} from './core.js';
import {
  create_generators,
  createApiId,
  messages_to_scalars
} from '../util.js';
import {
  octets_to_commitment_with_proof,
  prependBlindApiId
} from './util.js';
import {BLIND_API_ID} from '../constants.js';
import {getCiphersuite} from '../ciphersuites.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

export async function commit({
  committed_messages, api_id, ciphersuite,
  mocked_random_scalars_options
} = {}) {
  assertArray(committed_messages, 'committed_messages');
  ciphersuite = getCiphersuite(ciphersuite);

  if(api_id === undefined) {
    api_id = createApiId(ciphersuite.ciphersuite_id, BLIND_API_ID);
  }
  assertInstance(Uint8Array, api_id, 'api_id');

  /* Algorithm:

  1. committed_message_scalars = BBS.messages_to_scalars(
       committed_messages, api_id)
  2. blind_generators = BBS.create_generators(
       length(committed_message_scalars) + 1, 'BLIND_' || api_id)
  3. return CoreCommit(committed_message_scalars, blind_generators, api_id)

  */
  const committed_message_scalars = messages_to_scalars({
    messages: committed_messages, api_id, ciphersuite
  });
  const blind_generators = create_generators({
    count: committed_message_scalars.length + 1,
    api_id: prependBlindApiId({api_id}), ciphersuite
  });
  return CoreCommit({
    committed_message_scalars, blind_generators,
    api_id, ciphersuite, mocked_random_scalars_options
  });
}

export function deserialize_and_validate_commit({
  commitment_with_proof,
  blind_generators, api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Algorithm:

  1.  if commitment_with_proof is the empty string (""), return Identity_G1
  2.  com_res = octets_to_commitment_with_proof(commitment_with_proof)
  3.  if com_res is INVALID, return INVALID
  4.  (commit, commit_proof) = com_res
  5.  if (length(commit_proof[1]) + 1) != length(blind_generators),
        return INVALID
  6.  validation_res = verify_commitment(commit, commit_proof,
                                         blind_generators, api_id)
  7. if validation_res is INVALID, return INVALID
  8. return commitment

  */
  if(commitment_with_proof.length === 0) {
    // Identity_G1 == ciphersuite.Identity_E1
    return ciphersuite.Identity_E1;
  }

  const {
    commitment, proof: commitment_proof
  } = octets_to_commitment_with_proof({
    commitment_with_proof_octets: commitment_with_proof, ciphersuite
  });

  /* Note: This is an implementation for step 5 above, that checks the
  number of messages in the commitment proof against the number of blind
  generators. In this implementation, `commitment_proof` is an array with
  >= 2 scalars, where the first and last scalars are always present and the
  middle scalars have a length of >= 0; and `length(commit_proof[1])` from the
  spec refers to the length of the middle scalars, which we compute here by
  subtracting the first and last (i.e., `commitment_proof.length - 2`) */
  const msg_commitments_count = commitment_proof.length - 2;
  if((msg_commitments_count + 1) !== blind_generators.length) {
    throw new Error(
      `The number of blind generators (${blind_generators.length}) must ` +
      'equal the number of message commitments ' +
      `(${msg_commitments_count}) + 1.`);
  }

  const validation_res = CoreCommitVerify({
    commitment, commitment_proof, blind_generators, api_id, ciphersuite
  });
  if(!validation_res) {
    throw new Error('Commitment verification failed.');
  }

  return commitment;
}
