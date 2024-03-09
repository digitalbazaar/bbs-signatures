/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import {CIPHERSUITES_TEST_VECTORS} from './blind-test-vectors.js';
import {
  Commit
} from '../lib/bbs/blind/interface.js';
chai.should();

const OPERATIONS = {
  Commit
};

describe('Blind BBS test vectors', () => {
  const only = CIPHERSUITES_TEST_VECTORS.filter(tv => {
    return tv.fixtures.some(({only}) => only);
  });
  const testCiphersuites = only.length > 0 ? only : CIPHERSUITES_TEST_VECTORS;
  for(const tv of testCiphersuites) {
    const {ciphersuite, fixtures} = tv;
    describe(ciphersuite.name, () => {
      const only = fixtures.filter(({only}) => only);
      const tests = only.length > 0 ? only : fixtures;
      for(const {name, operation, parameters, output} of tests) {
        const op = OPERATIONS[operation];
        if(!op) {
          throw new Error(`Unknown operation "${operation}".`);
        }
        it(operation + ' - ' + name, async () => {
          const result = await op({...parameters, ciphersuite});
          result.should.deep.eql(output);
        });
      }
    });
  }
});
