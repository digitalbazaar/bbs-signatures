/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {messages_to_scalars} from './util.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

// FIXME: could accept `pid_scalar` as an optimization
export function CalculatePseudonym({
  verifier_id, pid, api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Algorithm:

  1. OP = hash_to_curve_g1(verifier_id, api_id)
  2. if OP is INVALID, return INVALID
  3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  3. pid_scalar = messages_to_scalars((pid), api_id)
  4. return OP * pid_scalar

  */
  const OP = ciphersuite.hash_to_curve_g1(verifier_id, api_id);
  // Identity_G1 == ciphersuite.E1.ONE
  const {BP1, P1, E1} = ciphersuite;
  if(E1.eql(OP, E1.ONE) || E1.eql(OP, BP1) || E1.eql(OP, P1)) {
    throw new Error('Invalid verifier ID.');
  }
  const messages = [pid];
  const pid_scalar = messages_to_scalars({messages, api_id, ciphersuite});
  return OP.multiply(pid_scalar);
}
