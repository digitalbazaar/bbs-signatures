/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {assertArray, assertInstance, assertType} from './assert.js';
import {KeyGen, SkToPk} from './bbs/keypair.js';
import {ProofGen, ProofVerify, Sign, Verify} from './bbs/interface.js';
import {getCiphersuite} from './bbs/ciphersuites.js';
import {mod} from '@noble/curves/abstract/modular';
import {os2ip} from './bbs/util.js';
import {webcrypto} from './crypto.js';

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
    secretKey: key_material,
    publicKey: PK
  };
}

export async function sign({
  secretKey, publicKey, header, messages, ciphersuite,
  // enable reuse of safely generated secret key scalars vs. just key material
  safeSecretKeyScalarBytes
} = {}) {
  ciphersuite = getCiphersuite(ciphersuite);
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));

  // load `SK`
  let SK;
  // check `safeSecretKeyScalarBytes` first so any potential assertion errors
  // recommend `secretKey` over it
  if(safeSecretKeyScalarBytes !== undefined) {
    if(secretKey !== undefined) {
      throw new Error(
        'Only one of "secretKey" or "safeSecretKeyScalarBytes" is allowed.');
    }
    SK = _secretKeyScalarFromBytes({safeSecretKeyScalarBytes, ciphersuite});
  } else {
    assertInstance(Uint8Array, secretKey, 'secretKey');
    SK = KeyGen({key_material: secretKey, ciphersuite});
  }

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

// utility function to load a secret key scalar from bytes; only to be used
// with safely-generated and serialized `SK` values
function _secretKeyScalarFromBytes({
  safeSecretKeyScalarBytes, ciphersuite
} = {}) {
  assertInstance(
    Uint8Array, safeSecretKeyScalarBytes, 'safeSecretKeyScalarBytes');
  const {octet_scalar_length, r} = ciphersuite;
  const sk = mod(os2ip(safeSecretKeyScalarBytes, octet_scalar_length), r);
  if(sk === 0n) {
    throw new Error('Invalid scalar secret key value of "0".');
  }
  return sk;
}
