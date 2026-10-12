/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
// The BBS pseudonym draft's own test fixtures
// (draft-irtf-cfrg-bbs-per-verifier-linkability, vector `nym_secrets`).
import {
  b2h, disclosed, h2b, h2s, loadFixtures, mockedOptions, SPEC_CIPHERSUITES
} from './spec-fixtures.js';
import {
  BlindSignWithNym, BlindVerifyWithNym, NymCommit,
  ProofGenWithPseudonym, ProofVerifyWithPseudonym
} from '../lib/bbs/pseudonym/interface.js';
import chai from 'chai';
chai.should();

const SPEC = 'pseudonym';

describe('BBS pseudonym spec fixtures', () => {
  for(const {dir, ciphersuite} of SPEC_CIPHERSUITES) {
    describe(ciphersuite.name, () => {
      for(const fx of loadFixtures(SPEC, dir, 'nymCommit')) {
        it(`nymCommit ${fx.file}: ${fx.caseName}`, async () => {
          const {commitment_with_proof, secret_prover_blind} = await NymCommit({
            prover_nyms: fx.proverNyms.map(h2s),
            committed_messages: fx.committedMessages.map(h2b), ciphersuite,
            mocked_random_scalars_options: mockedOptions(
              fx.mockRngParameters, fx.mockRngParameters.commit)
          });
          b2h(commitment_with_proof).should.equal(fx.commitmentWithProof);
          secret_prover_blind.should.equal(h2s(fx.proverBlind));
        });
      }

      for(const fx of loadFixtures(SPEC, dir, 'nymSignature')) {
        it(`nymSignature ${fx.file}: ${fx.caseName}`, async () => {
          const {secretKey, publicKey} = fx.signerKeyPair;
          const common = {
            PK: h2b(publicKey), header: h2b(fx.header),
            messages: fx.messages.map(h2b), ciphersuite
          };
          const signer_nym_entropy = h2s(fx.signer_nym_entropy);
          const signature = await BlindSignWithNym({
            ...common, SK: h2s(secretKey),
            commitment_with_proof: h2b(fx.commitmentWithProof),
            length_nym_vector: fx.proverNyms.length,
            signer_nym_entropy
          });
          b2h(signature).should.equal(fx.signature);
          const {verified, nym_secrets} = await BlindVerifyWithNym({
            ...common, signature,
            committed_messages: fx.committedMessages.map(h2b),
            prover_nyms: fx.proverNyms.map(h2s),
            signer_nym_entropy,
            secret_prover_blind: h2s(fx.proverBlind)
          });
          verified.should.equal(fx.result.valid);
          nym_secrets.should.deep.equal(fx.nym_secrets.map(h2s));
        });
      }

      for(const fx of loadFixtures(SPEC, dir, 'nymProof')) {
        it(`nymProof ${fx.file}: ${fx.caseName}`, async () => {
          const revealed = disclosed(fx.revealedMessages);
          const revealedCommitted = disclosed(fx.revealedCommittedMessages);
          const common = {
            PK: h2b(fx.signerPublicKey), header: h2b(fx.header),
            ph: h2b(fx.presentationHeader), context_id: h2b(fx.context_id),
            ciphersuite
          };
          const verified = await ProofVerifyWithPseudonym({
            ...common, proof: h2b(fx.proof), pseudonym: h2b(fx.pseudonym),
            length_nym_vector: fx.nym_secrets.length, L: fx.L,
            disclosed_messages: revealed.messages,
            disclosed_committed_messages: revealedCommitted.messages,
            disclosed_indexes: revealed.indexes,
            disclosed_committed_indexes: revealedCommitted.indexes
          });
          verified.should.equal(fx.result.valid);
          if(!fx.result.valid) {
            return;
          }
          const {proof, pseudonym} = await ProofGenWithPseudonym({
            ...common, signature: h2b(fx.signature),
            nym_secrets: fx.nym_secrets.map(h2s),
            messages: fx.messages.map(h2b),
            disclosed_indexes: revealed.indexes,
            committed_messages: fx.committedMessages.map(h2b),
            disclosed_committed_indexes: revealedCommitted.indexes,
            secret_prover_blind: h2s(fx.proverBlind),
            mocked_random_scalars_options: mockedOptions(
              fx.mockRngParameters, fx.mockRngParameters.proof)
          });
          b2h(pseudonym).should.equal(fx.pseudonym);
          b2h(proof).should.equal(fx.proof);
        });
      }
    });
  }
});
