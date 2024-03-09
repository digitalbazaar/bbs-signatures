/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {os2ip} from '../../lib/bbs/util.js';

export const TEXT_ENCODER = new TextEncoder();

export const MESSAGES = [
  h2b('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02'),
  h2b('c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80'),
  h2b('7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73'),
  h2b('77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c'),
  h2b('496694774c5604ab1b2544eababcf0f53278ff50'),
  h2b('515ae153e22aae04ad16f759e07237b4'),
  h2b('d183ddc6e2665aa4e2f088af'),
  h2b('ac55fb33a75909ed'),
  h2b('96012096'),
  h2b('')
];

export const COMMITTED_MESSAGES = [
  h2b('5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3'),
  h2b('a75d8b634891af92282cc81a675972d1929d3149863c1fc0'),
  h2b('835889a40744813a892eff9deb1edaeb'),
  h2b('e1ca9729410dc6ba'),
  h2b('')
];

// hex => bytes
export function h2b(hex) {
  if(hex.length === 0) {
    return new Uint8Array();
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map(h => parseInt(h, 16)));
}

// hex => scalar (bigint)
export function h2s(hex) {
  return os2ip(h2b(hex));
}
