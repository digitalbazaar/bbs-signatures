/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  calculate_domain,
  concatBytes,
  hash_to_scalar,
  serialize, signature_to_octets,
  TEXT_ENCODER
} from '../util.js';
import {deserialize_and_validate_commit} from './commitment.js';

// Note: This file uses naming conventions that match the IETF BBS RFC:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html

export function CoreBlindSign({
  SK, PK, generators,
  commitment_with_proof = new Uint8Array(),
  header = new Uint8Array(), messages = [],
  signer_blind = 0n,
  api_id = new Uint8Array(), ciphersuite
} = {}) {
  /* Definitions:

  1. signature_dst, an octet string representing the domain separation
                    tag: api_id || "H2S_" where "H2S_" is an ASCII string
                    comprised of 4 bytes.
  */
  const signature_dst = concatBytes(api_id, TEXT_ENCODER.encode('H2S_'));

  /* Deserialization:

  1. L = length(messages)
  2. (msg_1, ..., msg_L) = messages
  3. commit_res = deserialize_and_validate_commit(
                    commitment_with_proof, generators, api_id)
  4. if commit_res is INVALID, return INVALID
  // if commitment_with_proof == "", then commit_res = (Identity_G1, 0).
  5. (commit, M) = commit_res
  6. Q_1 = generators[0]
  7. Q_2 = Identity_G1
  8. if commitment_with_proof != "", Q_2 = generators[1]
  9. (H_1, ..., H_L) = generators[M + 1..M + L + 1]

  */
  const L = messages.length;
  if(generators.length !== (L + 2)) {
    throw new Error(
      `"generators.length" (${generators.length}) must equal ` +
      `"messages.length" (${messages.length}) + 2.`);
  }
  const [commitment, M] = deserialize_and_validate_commit({
    commitment_with_proof, generators, api_id, ciphersuite
  });
  const {Q_1} = generators;
  // Identity_G1 == ciphersuite.E1.ONE
  const Q_2 = commitment_with_proof.length === 0 ?
    ciphersuite.E1.ONE : generators[1];
  const H = generators.slice(M + 1, M + L + 2);

  /* Algorithm:

  1. domain = calculate_domain(PK, generators, header, api_id)
  2. e_octs = serialize((SK, domain, msg_1, ..., msg_L, signer_blind))
  3. e = BBS.hash_to_scalar(
           e_octs || commitment_with_proof, signature_dst)
  // if a commitment is not supplied, Q_2 = Identity_G1, meaning that
  // signer_blind will be ignored.
  4. commit = commit + Q_2 * signer_blind
  5. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  6. A = B * (1 / (SK + e))
  7. return signature_to_octets((A, e))
  8. return signature

  */
  const domain = calculate_domain({
    PK, generators, header, api_id, ciphersuite
  });
  const e_octs = serialize({
    input_array: [SK, domain, ...messages, signer_blind], ciphersuite
  });
  const e = hash_to_scalar({
    msg_octets: concatBytes(e_octs, commitment_with_proof),
    dst: signature_dst,
    ciphersuite
  });
  const commit = commitment.add(Q_2.multiply(signer_blind));

  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  const {P1} = ciphersuite;
  let B = P1.add(Q_1.multiply(domain));
  let i = 0;
  for(const message of messages) {
    B = B.add(H[i++].multiply(message));
  }
  B = B.add(commit);

  // A = B * (1 / (SK + e))
  // multiply `B` by the inverse of `SK + e` within the field over `r`
  const {Fr} = ciphersuite;
  const A = B.multiply(Fr.inv(Fr.add(SK, e)));
  // if A == Identity_G1 throw invalid signature error
  if(ciphersuite.E1.eql(A, ciphersuite.E1.ONE)) {
    throw new Error('Invalid signature.');
  }
  return signature_to_octets({signature: [A, e], ciphersuite});
}
