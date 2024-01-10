/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ProofGen,
  ProofVerify,
  Sign,
  Verify
} from './bbs/interface.js';
import {KeyGen, SkToPk} from './bbs/assert.js';
import {assertArray, assertInstance} from './bbs/assert.js';
import {getCiphersuite} from './bbs/ciphersuites.js';
import {webcrypto} from './crypto.js';

// generates BLS12-381 key pair
export async function generateKeyPair({ciphersuite} = {}) {
  // generate `key_material`
  const key_material = await webcrypto.getRandomValues(
    new Uint8Array(ciphersuite.octet_scalar_length));

  // generate `SK` to get `PK`
  ciphersuite = getCiphersuite(ciphersuite);
  const SK = KeyGen({key_material, ciphersuite});
  const PK = SkToPk({SK, ciphersuite});

  // return `key_material` as secret key and `PK` as public key
  return {
    secretKey: key_material,
    publicKey: PK
  };
}

export async function sign({
  secretKey, publicKey, header, messages, ciphersuite
} = {}) {
  assertInstance(Uint8Array, secretKey, 'secretKey');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));

  // load `SK`
  ciphersuite = getCiphersuite(ciphersuite);
  const SK = KeyGen({key_material: secretKey, ciphersuite});

  // load `PK`
  if(publicKey !== undefined) {
    assertInstance(Uint8Array, publicKey, 'publicKey');
    publicKey = SkToPk({SK, ciphersuite});
  }

  return Sign({SK, PK, header, messages, ciphersuite});
}

export async function verifySignature({
  publicKey, signature, header, messages, ciphersuite
} = {}) {
  assertInstance(Uint8Array, publicKey, 'publicKey');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(messages, 'messages');
  messages.forEach((m, i) => assertInstance(Uint8Array, m, `messages[${i}]`));

  return Verify({PK, signature, header, messages, ciphersuite});
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
    PK, signature, header, ph: presentationHeader,
    messages, disclosed_indexes: disclosedMessageIndexes, ciphersuite
  });
}

export async function verifyProof({
  publicKey, proof, header,
  presentationHeader, disclosedMessages, disclosedMessageIndexes,
  ciphersuite
} = {}) {
  assertInstance(Uint8Array, publicKey, 'publicKey');
  assertInstance(Uint8Array, signature, 'signature');
  assertInstance(Uint8Array, header, 'header');
  assertArray(disclosedMessages, 'disclosedMessages');
  disclosedMessages.forEach(
    (m, i) => assertInstance(Uint8Array, m, `disclosedMessages[${i}]`));
  assertInstance(Uint8Array, presentationHeader, 'presentationHeader');
  assertArray(disclosedMessageIndexes, 'disclosedMessageIndexes');
  disclosedMessageIndexes.forEach(
    (idx, i) => assertType('number', idx, `disclosedMessageIndexes[${i}]`));

  return ProofVerify({
    PK, proof, header, ph: presentationHeader,
    disclosed_messages: disclosedMessageIndexes,
    disclosed_indexes: disclosedMessageIndexes,
    ciphersuite
  });
}
