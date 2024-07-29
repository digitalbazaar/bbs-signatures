/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  BlindProofGen, BlindProofVerify, BlindSign, BlindVerify, Commit
} from '../lib/bbs/blind/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './blind-test-vectors.js';
import {mocked_calculate_random_scalars} from '../lib/bbs/util.js';
chai.should();

const OPERATIONS = {
  BlindSignAndBlindVerify,
  BlindVerifyAndBlindProofGen,
  Commit, CommitAndBlindSignAndBlindVerify,
  BlindProofVerify
};

describe('Blind BBS test vectors', () => {
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

// runs `BlindSign` and then `BlindVerify`
async function BlindSignAndBlindVerify({
  SK, PK,
  commitment_with_proof,
  header = new Uint8Array(),
  messages = [],
  committed_messages,
  secret_prover_blind,
  signer_blind,
  ciphersuite,
  signature_mocked_random_scalars_options
} = {}) {
  if(signer_blind !== 0n) {
    const [test_signer_blind] = await mocked_calculate_random_scalars({
      ...signature_mocked_random_scalars_options, ciphersuite
    });
    test_signer_blind.should.eql(signer_blind);
  }
  const signature = await BlindSign({
    SK, PK, commitment_with_proof,
    header, messages, signer_blind, ciphersuite
  });
  const verified = await BlindVerify({
    PK, signature, header,
    messages, committed_messages,
    secret_prover_blind,
    signer_blind,
    ciphersuite
  });
  return {signature, verified};
}

// runs `BlindVerify` and `BlindProofGen`
async function BlindVerifyAndBlindProofGen({
  PK,
  signature,
  header = new Uint8Array(),
  ph = new Uint8Array(),
  messages = [], disclosed_indexes,
  committed_messages, disclosed_commitment_indexes,
  secret_prover_blind,
  signer_blind,
  ciphersuite,
  proof_mocked_random_scalars_options
} = {}) {
  const verifyResult = await BlindVerify({
    PK, signature, header,
    messages, committed_messages,
    secret_prover_blind,
    signer_blind,
    ciphersuite
  });
  verifyResult.should.equal(true);
  return BlindProofGen({
    PK, signature,
    header, ph,
    messages, disclosed_indexes,
    committed_messages, disclosed_commitment_indexes,
    secret_prover_blind, signer_blind,
    ciphersuite,
    mocked_random_scalars_options: proof_mocked_random_scalars_options
  });
}

// runs `Commit`, `BlindSign`, then `BlindVerify`
async function CommitAndBlindSignAndBlindVerify({
  SK, PK,
  commitment_with_proof,
  header = new Uint8Array(),
  messages = [],
  committed_messages,
  secret_prover_blind,
  signer_blind,
  ciphersuite,
  commit_mocked_random_scalars_options,
  signature_mocked_random_scalars_options
} = {}) {
  const commitResult = await Commit({
    committed_messages, ciphersuite,
    mocked_random_scalars_options: commit_mocked_random_scalars_options
  });
  commitResult[0].should.deep.eql(commitment_with_proof);
  commitResult[1].should.deep.eql(secret_prover_blind);
  if(signer_blind !== 0n) {
    const [test_signer_blind] = await mocked_calculate_random_scalars({
      ...signature_mocked_random_scalars_options, ciphersuite
    });
    test_signer_blind.should.eql(signer_blind);
  }
  const signature = await BlindSign({
    SK, PK, commitment_with_proof,
    header, messages, signer_blind, ciphersuite
  });
  const verified = await BlindVerify({
    PK, signature, header,
    messages, committed_messages,
    secret_prover_blind,
    signer_blind,
    ciphersuite
  });
  return {signature, verified};
}
