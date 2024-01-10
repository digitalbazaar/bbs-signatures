/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs from '../lib/index.js';
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './bbs-test-vectors.js';
chai.should();
const {expect} = chai;

const ciphersuite = 'BLS12-381-SHA-256';
const BLS12381_SHA256_TVS = CIPHERSUITES_TEST_VECTORS[1];

describe('API', () => {
  describe('generateKeyPair()', () => {
    it('should pass', async () => {
      const {secretKey, publicKey} = await bbs.generateKeyPair({ciphersuite});
      secretKey.should.be.a('Uint8Array');
      secretKey.length.should.eql(32);
      publicKey.should.be.a('Uint8Array');
      publicKey.length.should.eql(96);
    });
    it('should fail when "cryptosuite" is missing', async () => {
      let err;
      try {
        await bbs.generateKeyPair();
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
    });
  });

  describe('sign()', () => {
    it('should pass', async () => {
      const {secretKey, publicKey} = await bbs.generateKeyPair({ciphersuite});
      const signature = await bbs.sign({
        secretKey,
        publicKey,
        header: new Uint8Array(),
        messages: [new Uint8Array()],
        ciphersuite
      });
      signature.should.be.a('Uint8Array');
      signature.length.should.eql(80);
    });
    it('should pass without passing "publicKey"', async () => {
      const {secretKey} = await bbs.generateKeyPair({ciphersuite});
      const signature = await bbs.sign({
        secretKey,
        header: new Uint8Array(),
        messages: [new Uint8Array()],
        ciphersuite
      });
      signature.should.be.a('Uint8Array');
      signature.length.should.eql(80);
    });
    it('should fail when "secretKey" is missing', async () => {
      const {publicKey} = await bbs.generateKeyPair({ciphersuite});

      let err;
      try {
        await bbs.sign({
          publicKey,
          header: new Uint8Array(),
          messages: [new Uint8Array()],
          ciphersuite
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
    });
  });

  describe('verifySignature()', () => {
    it('should verify signature produced using sign()', async () => {
      const {secretKey, publicKey} = await bbs.generateKeyPair({ciphersuite});
      const header = new Uint8Array();
      const messages = [new TextEncoder().encode('msg')];
      const signature = await bbs.sign({
        secretKey,
        header,
        messages,
        ciphersuite
      });
      const verified = await bbs.verifySignature({
        publicKey,
        signature,
        header,
        messages,
        ciphersuite
      });
      verified.should.eql(true);
    });
    it('should pass a test vector', async () => {
      const {parameters} = BLS12381_SHA256_TVS.fixtures.find(
        ({name, operation}) => operation === 'Verify' &&
          name.startsWith('Valid Multi-Message'));

      const verified = await bbs.verifySignature({
        publicKey: parameters.PK,
        signature: parameters.signature,
        header: parameters.header,
        messages: parameters.messages,
        ciphersuite
      });
      verified.should.eql(true);
    });
    it('should fail to verify modified message', async () => {
      const {parameters} = BLS12381_SHA256_TVS.fixtures.find(
        ({name, operation}) => operation === 'Verify' &&
          name.startsWith('Modified Message'));

      const verified = await bbs.verifySignature({
        publicKey: parameters.PK,
        signature: parameters.signature,
        header: parameters.header,
        messages: parameters.messages,
        ciphersuite
      });
      verified.should.eql(false);
    });
  });

  describe('deriveProof()', () => {
    it('should derive proof from signature produced using sign()', async () => {
      const {secretKey, publicKey} = await bbs.generateKeyPair({ciphersuite});
      const header = new Uint8Array();
      const messages = [new TextEncoder().encode('msg')];
      const signature = await bbs.sign({
        secretKey,
        header,
        messages,
        ciphersuite
      });
      const proof = await bbs.deriveProof({
        publicKey,
        signature,
        header,
        messages,
        presentationHeader: new Uint8Array(),
        disclosedMessageIndexes: [0],
        ciphersuite
      });
      proof.should.be.a('Uint8Array');
      proof.length.should.eql(272);
    });
    it('should fail when "signature" is missing', async () => {
      const {publicKey} = await bbs.generateKeyPair({ciphersuite});
      const header = new Uint8Array();
      const messages = [new TextEncoder().encode('msg')];

      let err;
      try {
        await bbs.deriveProof({
          publicKey,
          header,
          messages,
          presentationHeader: new Uint8Array(),
          disclosedMessageIndexes: [0],
          ciphersuite
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
    });
  });

  describe('verifyProof()', () => {
    it('should verify a proof produced using deriveProof()', async () => {
      const {secretKey, publicKey} = await bbs.generateKeyPair({ciphersuite});
      const header = new Uint8Array();
      const messages = [new TextEncoder().encode('msg')];
      const signature = await bbs.sign({
        secretKey,
        header,
        messages,
        ciphersuite
      });
      const proof = await bbs.deriveProof({
        publicKey,
        signature,
        header,
        messages,
        presentationHeader: new Uint8Array(),
        disclosedMessageIndexes: [0],
        ciphersuite
      });
      const verified = await bbs.verifyProof({
        publicKey,
        proof,
        header,
        presentationHeader: new Uint8Array(),
        disclosedMessages: messages,
        disclosedMessageIndexes: [0],
        ciphersuite
      });
      verified.should.eql(true);
    });
    it('should pass a test vector', async () => {
      const {parameters} = BLS12381_SHA256_TVS.fixtures.find(
        ({name, operation}) => operation === 'ProofVerify' &&
          name.startsWith('Valid Multi-Message'));

      const verified = await bbs.verifyProof({
        publicKey: parameters.PK,
        proof: parameters.proof,
        header: parameters.header,
        presentationHeader: parameters.ph,
        disclosedMessages: parameters.disclosed_messages,
        disclosedMessageIndexes: parameters.disclosed_indexes,
        ciphersuite
      });
      verified.should.eql(true);
    });
    it('should fail to verify modified message', async () => {
      const {parameters} = BLS12381_SHA256_TVS.fixtures.find(
        ({name, operation}) => operation === 'ProofVerify' &&
          name.startsWith('Modified Message'));

      const verified = await bbs.verifyProof({
        publicKey: parameters.PK,
        proof: parameters.proof,
        header: parameters.header,
        presentationHeader: parameters.ph,
        disclosedMessages: parameters.disclosed_messages,
        disclosedMessageIndexes: parameters.disclosed_indexes,
        ciphersuite
      });
      verified.should.eql(false);
    });
  });
});
