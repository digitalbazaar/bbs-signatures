/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {BlindSign, BlindVerify} from '../lib/bbs/blind/interface.js';
import {
  CalculatePseudonym, NymCommit,
  ProofGenWithPseudonym, ProofVerifyWithPseudonym
} from '../lib/bbs/pseudonym/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './pseudonym-test-vectors.js';
import {mocked_calculate_random_scalars} from '../lib/bbs/util.js';
chai.should();

const OPERATIONS = {
  CalculatePseudonym,
  CommitAndBlindSignWithNymAndBlindVerify,
  PidVerifyAndProofGenWithPseudonym,
  ProofVerifyWithPseudonym,
  // FIXME: remove `PidSignAndVerify`
  PidSignAndVerify,
  NymCommit
};

describe.only('Pseudonym BBS test vectors', () => {
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

// FIXME: remove me
async function PidSignAndVerify() {}

// runs `Commit`, `BlindSign`, then `BlindVerify`
async function CommitAndBlindSignWithNymAndBlindVerify({
  SK, PK,
  commitment_with_proof,
  header = new Uint8Array(),
  messages = [],
  prover_nym,
  committed_messages,
  secret_prover_blind,
  ciphersuite,
  commit_mocked_random_scalars_options
} = {}) {
  const commitResult = await NymCommit({
    prover_nym, committed_messages, ciphersuite,
    mocked_random_scalars_options: commit_mocked_random_scalars_options
  });
  commitResult[0].should.deep.eql(commitment_with_proof);
  commitResult[1].should.deep.eql(secret_prover_blind);
  const signature = await BlindSign({
    SK, PK, commitment_with_proof,
    header, messages, ciphersuite
  });
  const verified = await BlindVerify({
    PK, signature, header,
    messages, committed_messages,
    secret_prover_blind,
    ciphersuite
  });
  return {signature, verified};
}

// runs `BlindVerify` w/`pid` and `ProofGenWithPseudonym`
async function PidVerifyAndProofGenWithPseudonym({
  PK,
  signature,
  verifier_id, pseudonym, pid,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes,
  secret_prover_blind,
  signer_blind,
  api_id, ciphersuite,
  proof_mocked_random_scalars_options
} = {}) {
  const verifyResult = await BlindVerify({
    PK, signature, header,
    messages: [...messages, pid], committed_messages: [],
    secret_prover_blind,
    signer_blind,
    api_id, ciphersuite
  });
  verifyResult.should.equal(true);
  const x = await ProofGenWithPseudonym({
  //return ProofGenWithPseudonym({
    PK, signature,
    pseudonym, verifier_id, pid,
    header, ph,
    messages, disclosed_indexes,
    api_id, ciphersuite,
    mocked_random_scalars_options: proof_mocked_random_scalars_options
  });
  console.log('x', Buffer.from(x).toString('hex'));
  return x;
}
