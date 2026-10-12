/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
// The Blind BBS draft's own test fixtures
// (draft-irtf-cfrg-bbs-blind-signatures).
import {
  b2h, disclosed, h2b, h2s, loadFixtures, loadMessages, mockedOptions,
  SPEC_CIPHERSUITES
} from './spec-fixtures.js';
import {
  BlindProofGen, BlindProofVerify, BlindSign, BlindVerify, Commit
} from '../lib/bbs/blind/interface.js';
import chai from 'chai';
chai.should();

const SPEC = 'blind';
const ALL = loadMessages(SPEC);
// commitment with proof = C (point) || s^ || m^_1..M || challenge
const committedCount = ({ciphersuite, commitmentWithProof}) => {
  const {octet_point_length: P, octet_scalar_length: S} = ciphersuite;
  if(!commitmentWithProof) {
    return 0;
  }
  return (h2b(commitmentWithProof).length - P - 2 * S) / S;
};

describe('Blind BBS spec fixtures', () => {
  for(const {dir, ciphersuite} of SPEC_CIPHERSUITES) {
    describe(ciphersuite.name, () => {
      for(const fx of loadFixtures(SPEC, dir, 'commit')) {
        it(`commit ${fx.file}: ${fx.caseName}`, async () => {
          const {commitment_with_proof, secret_prover_blind} = await Commit({
            committed_messages: fx.committedMessages.map(h2b), ciphersuite,
            mocked_random_scalars_options: mockedOptions(
              fx.mockRngParameters, fx.mockRngParameters.commit)
          });
          b2h(commitment_with_proof).should.equal(fx.commitmentWithProof);
          secret_prover_blind.should.equal(h2s(fx.proverBlind));
        });
      }

      for(const fx of loadFixtures(SPEC, dir, 'signature')) {
        it(`signature ${fx.file}: ${fx.caseName}`, async () => {
          const {secretKey, publicKey} = fx.signerKeyPair;
          const common = {
            PK: h2b(publicKey), header: h2b(fx.header),
            messages: fx.messages.map(h2b), ciphersuite
          };
          const signature = await BlindSign({
            ...common, SK: h2s(secretKey),
            commitment_with_proof: h2b(fx.commitmentWithProof ?? '')
          });
          b2h(signature).should.equal(fx.signature);
          const verified = await BlindVerify({
            ...common, signature,
            committed_messages: (fx.committedMessages ?? []).map(h2b),
            secret_prover_blind: fx.proverBlind ? h2s(fx.proverBlind) : 0n
          });
          verified.should.equal(fx.result.valid);
        });
      }

      for(const fx of loadFixtures(SPEC, dir, 'proof')) {
        it(`proof ${fx.file}: ${fx.caseName}`, async () => {
          const revealed = disclosed(fx.revealedMessages);
          const revealedCommitted = disclosed(fx.revealedCommittedMessages);
          const common = {
            PK: h2b(fx.signerPublicKey), header: h2b(fx.header),
            ph: h2b(fx.presentationHeader), ciphersuite
          };
          const verified = await BlindProofVerify({
            ...common, proof: h2b(fx.proof), L: fx.L,
            disclosed_messages: revealed.messages,
            disclosed_committed_messages: revealedCommitted.messages,
            disclosed_indexes: revealed.indexes,
            disclosed_committed_indexes: revealedCommitted.indexes
          });
          verified.should.equal(fx.result.valid);
          if(!fx.result.valid) {
            return;
          }
          const proof = await BlindProofGen({
            ...common, signature: h2b(fx.signature),
            messages: ALL.messages.slice(0, fx.L),
            disclosed_indexes: revealed.indexes,
            committed_messages: ALL.committedMessages.slice(
              0, committedCount({ciphersuite, ...fx})),
            disclosed_committed_indexes: revealedCommitted.indexes,
            secret_prover_blind: fx.proverBlind ? h2s(fx.proverBlind) : 0n,
            mocked_random_scalars_options: mockedOptions(
              fx.mockRngParameters, fx.mockRngParameters.proof)
          });
          b2h(proof).should.equal(fx.proof);
        });
      }
    });
  }
});
