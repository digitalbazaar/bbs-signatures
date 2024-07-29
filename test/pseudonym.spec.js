/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {BlindSign, BlindVerify, Commit} from '../lib/bbs/blind/interface.js';
import {
  CalculatePseudonym, ProofGenWithPseudonym, ProofVerifyWithPseudonym
} from '../lib/bbs/pseudonym/interface.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './pseudonym-test-vectors.js';
import {mocked_calculate_random_scalars} from '../lib/bbs/util.js';
chai.should();

const OPERATIONS = {
  CalculatePseudonym,
  Commit,
  PidSignAndVerify,
  PidVerifyAndProofGenWithPseudonym,
  ProofVerifyWithPseudonym,
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

// runs `BlindSign` w/`pid` and then `BlindVerify`
async function PidSignAndVerify({
  SK, PK,
  pid = new Uint8Array(),
  header = new Uint8Array(),
  messages = [],
  secret_prover_blind,
  signer_blind,
  api_id, ciphersuite,
  signature_mocked_random_scalars_options
} = {}) {
  if(signer_blind !== 0n) {
    const [test_signer_blind] = await mocked_calculate_random_scalars({
      ...signature_mocked_random_scalars_options, ciphersuite
    });
    test_signer_blind.should.eql(signer_blind);
  }
  messages = [...messages, pid];
  const signature = await BlindSign({
    SK, PK, header, messages, signer_blind, api_id, ciphersuite
  });
  const verified = await BlindVerify({
    PK, signature, header,
    messages, committed_messages: [],
    secret_prover_blind,
    signer_blind,
    api_id, ciphersuite
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
  return ProofGenWithPseudonym({
    PK, signature,
    pseudonym, verifier_id, pid,
    header, ph,
    messages, disclosed_indexes,
    api_id, ciphersuite,
    mocked_random_scalars_options: proof_mocked_random_scalars_options
  });
}
