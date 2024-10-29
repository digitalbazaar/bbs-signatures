/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from './assert.js';
import {i2osp, os2ip} from './bbs/util.js';
import {KeyGen, SkToPk} from './bbs/keypair.js';
import {ProofGen, ProofVerify, Sign, Verify} from './bbs/interface.js';
import {getCiphersuite} from './bbs/ciphersuites.js';
import {mod} from '@noble/curves/abstract/modular';
import {webcrypto} from './crypto.js';

// export ciphersuite string constants for external use
export const CIPHERSUITES = {
  BLS12381_SHAKE256: 'BLS12-381-SHAKE-256',
  BLS12381_SHA256: 'BLS12-381-SHA-256'
};

// Note: The naming conventions used in `./bbs/*` files are based on the
// the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-06.html

// generates BLS12-381 key pair
export async function generateKeyPair({seed, ciphersuite} = {}) {
  // generate `key_material`
  ciphersuite = getCiphersuite(ciphersuite);
  const key_material = seed ?? await webcrypto.getRandomValues(
    new Uint8Array(ciphersuite.octet_scalar_length));

  // generate `SK` to get `PK`
  const SK = KeyGen({key_material, ciphersuite});
  const PK = SkToPk({SK, ciphersuite});

  // return `key_material` as secret key and `PK` as public key
  return {
    secretKey: i2osp(SK, ciphersuite.octet_scalar_length),
    publicKey: PK
  };
}

export async function secretKeyToPublicKey({secretKey, ciphersuite} = {}) {
  assertInstance(Uint8Array, secretKey, 'secretKey');
  ciphersuite = getCiphersuite(ciphersuite);

  const SK = _scalarFromSecretKey({secretKey, ciphersuite});
  const publicKey = SkToPk({SK, ciphersuite});
  return publicKey;
}

export async function sign({
  secretKey, publicKey, header, messages, ciphersuite
} = {}) {
  assertInstance(Uint8Array, secretKey, 'secretKey');
  ciphersuite = getCiphersuite(ciphersuite);
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));

  // load `SK`
  const SK = _scalarFromSecretKey({secretKey, ciphersuite});

  // load `PK`
  if(publicKey !== undefined) {
    assertInstance(Uint8Array, publicKey, 'publicKey');
  } else {
    publicKey = SkToPk({SK, ciphersuite});
  }

  return Sign({SK, PK: publicKey, header, messages, ciphersuite});
}

export async function verifySignature({
  publicKey, signature, header, messages, ciphersuite
} = {}) {
  assertInstance(Uint8Array, publicKey, 'publicKey');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));

  return Verify({PK: publicKey, signature, header, messages, ciphersuite});
}

export async function deriveProof({
  publicKey, signature, header, messages,
  presentationHeader, disclosedMessageIndexes,
  ciphersuite
} = {}) {
  assertInstance(Uint8Array, publicKey, 'publicKey');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));
  assertInstance(Uint8Array, presentationHeader, 'presentationHeader');
  assertArray(disclosedMessageIndexes, 'disclosedMessageIndexes');
  disclosedMessageIndexes.forEach(
    (idx, i) => assertType('number', idx, `disclosedMessageIndexes[${i}]`));

  return ProofGen({
    PK: publicKey, signature, header, ph: presentationHeader,
    messages, disclosed_indexes: disclosedMessageIndexes, ciphersuite
  });
}

export async function verifyProof({
  publicKey, proof, header,
  presentationHeader, disclosedMessages, disclosedMessageIndexes,
  ciphersuite
} = {}) {
  assertInstance(Uint8Array, publicKey, 'publicKey');
  assertInstance(Uint8Array, proof, 'proof');
  assertInstance(Uint8Array, header, 'header');
  assertInstance(Uint8Array, presentationHeader, 'presentationHeader');
  assertArray(disclosedMessages, 'disclosedMessages');
  disclosedMessages.forEach(
    (m, i) => assertInstance(Uint8Array, m, `disclosedMessages[${i}]`));
  assertArray(disclosedMessageIndexes, 'disclosedMessageIndexes');
  disclosedMessageIndexes.forEach(
    (idx, i) => assertType('number', idx, `disclosedMessageIndexes[${i}]`));

  return ProofVerify({
    PK: publicKey, proof, header, ph: presentationHeader,
    disclosed_messages: disclosedMessages,
    disclosed_indexes: disclosedMessageIndexes,
    ciphersuite
  });
}

// utility function to load a secret scalar from secret key bytes
function _scalarFromSecretKey({secretKey, ciphersuite} = {}) {
  const {octet_scalar_length, r} = ciphersuite;
  const sk = mod(os2ip(secretKey, octet_scalar_length), r);
  if(sk === 0n) {
    throw new Error('Invalid secret key scalar value of "0".');
  }
  return sk;
}
