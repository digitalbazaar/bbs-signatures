/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  BlindSignWithNym, BlindVerifyWithNym,
  NymCommit, ProofGenWithPseudonym, ProofVerifyWithPseudonym
} from '../lib/bbs/pseudonym/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './pseudonym-test-vectors.js';
chai.should();

const OPERATIONS = {
  NymCommit,
  NymCommitAndBlindSignWithNymAndBlindVerify,
  NymProofGenAndProofVerify
};

describe('Pseudonym BBS test vectors', () => {
  const only = CIPHERSUITES_TEST_VECTORS.filter(tv => {
    return tv.fixtures.some(({only}) => only);
  });
  const testCiphersuites = only.length > 0 ? only : CIPHERSUITES_TEST_VECTORS;
  for(const tv of testCiphersuites) {
    const {ciphersuite, fixtures} = tv;
    describe(ciphersuite.name, () => {
      const only = fixtures.filter(({only}) => only);
      const tests = only.length > 0 ? only : fixtures;
      for(const {name, operation, parameters, output, skip} of tests) {
        const op = OPERATIONS[operation];
        if(!op) {
          throw new Error(`Unknown operation "${operation}".`);
        }
        const fn = skip ? it.skip : it;
        fn(operation + ' - ' + name, async () => {
          const result = await op({...parameters, ciphersuite});
          result.should.deep.eql(output);
        });
      }
    });
  }
});

// runs `NymCommit`, `BlindSign`, then `BlindVerify`
async function NymCommitAndBlindSignWithNymAndBlindVerify({
  SK, PK,
  prover_nym,
  commitment_with_proof,
  header = new Uint8Array(),
  messages = [],
  committed_messages = [],
  signer_nym_entropy,
  secret_prover_blind,
  nym_secret,
  api_id,
  ciphersuite,
  mocked_random_scalars_options
} = {}) {
  const {
    commitment_with_proof: calculatedCommitment,
    secret_prover_blind: calculatedSecretProverBlind
  } = await NymCommit({
    prover_nym, committed_messages,
    api_id, ciphersuite,
    mocked_random_scalars_options
  });
  calculatedCommitment.should.deep.eql(commitment_with_proof);
  calculatedSecretProverBlind.should.deep.eql(secret_prover_blind);
  const signature = await BlindSignWithNym({
    SK, PK,
    commitment_with_proof,
    header, messages,
    signer_nym_entropy,
    api_id, ciphersuite
  });
  const {verified, nym_secret: computed_secret} = await BlindVerifyWithNym({
    PK, signature, header,
    messages, committed_messages,
    prover_nym, signer_nym_entropy,
    secret_prover_blind,
    api_id, ciphersuite
  });
  computed_secret.should.deep.eql(nym_secret);
  return {signature, verified};
}

// runs proof gen => proof verify
async function NymProofGenAndProofVerify({
  PK,
  signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [],
  committed_messages,
  signer_nym_entropy,
  prover_nym,
  secret_prover_blind,
  nym_secret,
  pseudonym,
  context_id,
  L,
  disclosed_messages, disclosed_indexes,
  disclosed_committed_messages, disclosed_commitment_indexes,
  api_id,
  ciphersuite,
  mocked_random_scalars_options
} = {}) {
  const {
    verified: signatureVerified, nym_secret: computed_secret
  } = await BlindVerifyWithNym({
    PK, signature, header,
    messages, committed_messages,
    prover_nym, signer_nym_entropy,
    secret_prover_blind,
    api_id, ciphersuite
  });
  signatureVerified.should.equal(true);
  computed_secret.should.deep.eql(nym_secret);

  const {proof, pseudonym: computed_pseudonym} = await ProofGenWithPseudonym({
    PK, signature,
    header, ph,
    nym_secret, context_id,
    messages, disclosed_indexes,
    committed_messages, disclosed_commitment_indexes,
    secret_prover_blind,
    api_id, ciphersuite,
    mocked_random_scalars_options
  });
  computed_pseudonym.should.deep.eql(pseudonym);

  const verified = ProofVerifyWithPseudonym({
    PK, proof,
    header,
    ph,
    pseudonym, context_id,
    L,
    disclosed_messages,
    disclosed_committed_messages,
    disclosed_indexes,
    disclosed_commitment_indexes,
    api_id, ciphersuite
  });
  return {proof, verified};
}
