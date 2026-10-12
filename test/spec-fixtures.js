/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
// The IETF CFRG draft repositories' own test fixtures, as written by
// `scripts/update-spec-fixtures.js` into `test/fixtures/spec/`.
import BLIND from './fixtures/spec/blind.js';
import {CIPHERSUITES} from '../lib/bbs/ciphersuites.js';
import PSEUDONYM from './fixtures/spec/pseudonym.js';

const SPECS = {blind: BLIND, pseudonym: PSEUDONYM};
const TEXT_ENCODER = new TextEncoder();

export const SPEC_CIPHERSUITES = [
  {dir: 'bls12-381-sha-256', ciphersuite: CIPHERSUITES.BLS12381_SHA256},
  {dir: 'bls12-381-shake-256', ciphersuite: CIPHERSUITES.BLS12381_SHAKE256}
];

// hex => bytes
export function h2b(hex) {
  return Uint8Array.from((hex ?? '').match(/../g) ?? [], b => parseInt(b, 16));
}

// hex => scalar; the fixtures write some scalars without leading zeros
// (odd-length hex), so parse them as numbers rather than as octets
export function h2s(hex) {
  return BigInt('0x' + hex);
}

export function b2h(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

// the spec's `mockRngParameters` entry for one operation => the options
// `mocked_calculate_random_scalars()` takes (`count` comes from the caller)
export function mockedOptions({SEED} = {}, {DST} = {}) {
  if(SEED === undefined || DST === undefined) {
    return undefined;
  }
  return {seed: TEXT_ENCODER.encode(SEED), dst: TEXT_ENCODER.encode(DST)};
}

export function loadMessages(spec) {
  const {messages, committedMessages} = SPECS[spec].messages;
  return {
    messages: messages.map(h2b),
    committedMessages: committedMessages.map(h2b)
  };
}

// the fixtures of one kind (e.g. `commit`) for one ciphersuite directory
export function loadFixtures(spec, dir, kind) {
  const fixtures = SPECS[spec][dir][kind];
  return Object.keys(fixtures).sort().map(name => ({
    file: `${name}.json`, ...fixtures[name]
  }));
}

// a fixture's `{index: hex}` disclosed-messages map => indexes and messages
export function disclosed(map) {
  map = map ?? {};
  const indexes = Object.keys(map).map(Number).sort((a, b) => a - b);
  return {indexes, messages: indexes.map(i => h2b(map[i]))};
}
