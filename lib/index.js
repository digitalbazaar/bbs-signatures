/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ALGORITHM,
  BLS12_381_CURVE,
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {createSigner, createVerifier} from './factory.js';
import {CryptoKey, webcrypto} from './crypto.js';
import {
  cryptoKeyfromRaw,
  exportKeyPair, importKeyPair,
  toPublicKeyBytes, toPublicKeyMultibase,
  toSecretKeyBytes, toSecretKeyMultibase
} from './serialize.js';

// generates BLS12-381 key pair
export async function generateKeyPair({} = {}) {
  // FIXME: add required cryptosuite ID param
  throw new Error('Not implemented.');
}

export async function sign({keyPair, header, messages} = {}) {
  throw new Error('Not implemented.');
}

export async function verifySignature({
  publicKey, signature, header, messages
} = {}) {
  throw new Error('Not implemented.');
}

export async function deriveProof({
  publicKey, signature, header, messages,
  presentationHeader, disclosedMessageIndexes
} = {}) {
  throw new Error('Not implemented.');
}

export async function verifyProof({
  publicKey, proof, header,
  presentationHeader, disclosedMessages, disclosedMessageIndexes
} = {}) {
  throw new Error('Not implemented.');
}
