/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {BLS12381_SHA256} from './fixtures/pseudonym-sha256.js';
import {BLS12381_SHAKE256} from './fixtures/pseudonym-shake256.js';

export const CIPHERSUITES_TEST_VECTORS = [
  BLS12381_SHA256,
  BLS12381_SHAKE256
];
