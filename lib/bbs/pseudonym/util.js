/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {blind_B_calculate} from '../blind/util.js';

// Note: This file uses naming conventions that match the IETF BBS RFCs.

// FIXME: attempt to consolidate with core `calculate_B()`
export function B_calculate_with_nym({
  generators, commitment, nym_generator, signer_nym_entropy,
  message_scalars, ciphersuite
} = {}) {
  /*
  Inputs:

  - generators (REQUIRED), an array of at least one point from the
                           G1 group.
  - commitment (REQUIRED), a point from the G1 group.
  - nym_generator (REQUIRED), a point from the G1 group.
  - signer_nym_entropy (REQUIRED), a random scalar.
  - message_scalars (OPTIONAL), an array of scalar values. If not
                                supplied, it defaults to the empty
                                array ("()").
  Outputs:
  - (B, signer_nym_entropy)

  Note: This function is the same as calling `B_calculate` from Blind BBS
  and then generating and adding `signer_nym_entropy`.

  /* Algorithm:

  1. B = blind_B_calculate(generators, commitment, message_scalars)
  2. signer_nym_entropy = get_random(1)
  3. B = B + nym_generator * signer_nym_entropy
  4. If B is Identity_G1, return INVALID
  5. return (B, signer_nym_entropy)

  */
  let B = blind_B_calculate({
    generators, commitment, message_scalars, ciphersuite
  });
  B = B.add(nym_generator.multiply(signer_nym_entropy));
  const {Identity_E1: Identity_G1} = ciphersuite;
  if(B.equals(Identity_G1)) {
    throw new Error('Invalid blind "B" value.');
  }

  return {B};
}
