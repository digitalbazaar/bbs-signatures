/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {BLS12381_SHA256} from './fixtures/blind-sha256.js';
import {BLS12381_SHAKE256} from './fixtures/blind-shake256.js';

export const CIPHERSUITES_TEST_VECTORS = [
  BLS12381_SHAKE256,
  BLS12381_SHA256
];
