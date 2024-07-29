/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  h2b, h2s,
  MESSAGES,
  TEXT_ENCODER
} from './common.js';
import {CIPHERSUITES} from '../../lib/bbs/ciphersuites.js';

/* eslint-disable max-len */
export const BLS12381_SHA256 = {
  ciphersuite: CIPHERSUITES.BLS12381_SHA256,
  key_material: h2b('746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579'),
  key_info: h2b('746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e'),
  key_dst: h2b('4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f'),
  SK: h2s('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc'),
  PK: h2b('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c'),
  pid: h2b('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  commit_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_')
  },
  signature_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_'),
    count: 1
  },
  proof_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_')
  }
};

BLS12381_SHA256.fixtures = [{
  name: 'Valid all-message signature',
  operation: 'PidSignAndVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    pid: BLS12381_SHA256.pid,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    secret_prover_blind: h2s(''),
    signer_blind: h2s(''),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('ad5d4ff88f21c3995c5ffffe85c3cf12c1da9af6569f7cf498b59bb6bbcb792abd739abf28ecad3afc7f31f43c1c496c63a9a7b292fadf8d31045a70d700ef26fa83bc4f4c4cbb83d63934b5cb521c23'),
    verified: true
  },
  debug: {
    B: h2b('94a7d4cc52bf32a5ba85a578d4a9099da034bb5c7792595053021a5052b380e05561f673b0c7b4678cce7977b8cdc016'),
    domain: h2b('453fd2677dc03f1a1432dbf2b2a079fdb69f05ae51a896616624f63706389825')
  }
}, {
  name: 'Pid as committed message commitment with proof',
  operation: 'Commit',
  parameters: {
    committed_messages: [BLS12381_SHA256.pid],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options: {
      seed: BLS12381_SHA256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 3
    }
  },
  output: [
    // commitment_with_proof
    h2b('b8458613044a81e52d721fa68ba8139fe9b2d9407edaa9b8f44ecdd7acd84a0ccfb5e1c6d0ad25f8da3925ba066b7868288f427597c084ddb9daf9f354b7b82d61f9ea90a2bbfda8bb28b96e06d6cb931a2b2c9a8c2d1ee44c6c3224b1347cd2fe105fbec7d1a0bda1fe857ba43a09ef57bbfc0fbf64164e403ef7ee05ddcddec5c28fda62a8248a262c2b213fa68eb2'),
    // secret_prover_blind
    h2s('3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041')
  ]
}, {
  name: 'CalculatePseudonym Example 1',
  operation: 'CalculatePseudonym',
  parameters: {
    pid: BLS12381_SHA256.pid,
    verifier_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_')
  },
  output: h2b('a48177347fd65ec55ebaf18a40e82292cfc9de91003dd9db2cfdceaf956ec3c1c096f8995d8b1f11800b20c5b62af5a4')
}, {
  name: 'Valid multi-message signature, multiple messages revealed proof',
  operation: 'PidVerifyAndProofGenWithPseudonym',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad5d4ff88f21c3995c5ffffe85c3cf12c1da9af6569f7cf498b59bb6bbcb792abd739abf28ecad3afc7f31f43c1c496c63a9a7b292fadf8d31045a70d700ef26fa83bc4f4c4cbb83d63934b5cb521c23'),
    verifier_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('a48177347fd65ec55ebaf18a40e82292cfc9de91003dd9db2cfdceaf956ec3c1c096f8995d8b1f11800b20c5b62af5a4'),
    pid: BLS12381_SHA256.pid,
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6],
    secret_prover_blind: h2s(''),
    signer_blind: h2s(''),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 12
    }
  },
  output: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2938b9d384a866a8f9bfee7981d893f9e5a4a3c22a9dc57e65e2ebce7bc5aa856b845b11fe69a97c11e82e0d710c84c8dadf182b16ec437ad26105ba1ecd9b08b52d4bddbc7b2436f6e1e1f086c76262feee24f78d2a3ec5a304b7243a7a3559b48c89257f83e44a1704db13094a8f462bc2b05407b7e8b53cd43ede7a004e3ea5fe272d55a4419f0b5120e2bb5354d04ae4326b42dd5bb385d20202a4be7ea6e73987e4aab6bb1bdecc46bef8cfe6eddbb46bb932656c967345d4a6431e6c31940ae42e6376c0d6ef0294c93a68c5665b907cdb167ebdb64de87fc5df13967535983a4f052990334cb5a855b46c26ab3e7b78e4e6e6b6b38d52d49f18a5517d02041c89d73f15c048a52e19a319d4cb04ccf9d68e9f3c7597cf614363fb9da4d5c8a98b67e026a5e83cbdc208a1d68b72b0dea1b79c8c4e088a2286796014b365d286fdacc0acd8988f8f2e023288f3a2ae2f9cbcd3d0ebcfcfb8930886087583cfa4c7e1450b984a7881aac3aea7a04cd3ca438520de2aab57340dd7d0e6edb598283c30090f87f3ecd98768e559d4881e33f2cf40c4b5a8052dbfb5489bb2e62af887e249b67737cafd13d6154b8fd0698e705ec5fc670ea64f1eb732f8d1f')
}, {
  skip: true,
  name: 'Valid multi-message signature, multiple messages revealed proof',
  operation: 'ProofVerifyWithPseudonym',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2938b9d384a866a8f9bfee7981d893f9e5a4a3c22a9dc57e65e2ebce7bc5aa856b845b11fe69a97c11e82e0d710c84c8dadf182b16ec437ad26105ba1ecd9b08b52d4bddbc7b2436f6e1e1f086c76262feee24f78d2a3ec5a304b7243a7a3559b48c89257f83e44a1704db13094a8f462bc2b05407b7e8b53cd43ede7a004e3ea5fe272d55a4419f0b5120e2bb5354d04ae4326b42dd5bb385d20202a4be7ea6e73987e4aab6bb1bdecc46bef8cfe6eddbb46bb932656c967345d4a6431e6c31940ae42e6376c0d6ef0294c93a68c5665b907cdb167ebdb64de87fc5df13967535983a4f052990334cb5a855b46c26ab3e7b78e4e6e6b6b38d52d49f18a5517d02041c89d73f15c048a52e19a319d4cb04ccf9d68e9f3c7597cf614363fb9da4d5c8a98b67e026a5e83cbdc208a1d68b72b0dea1b79c8c4e088a2286796014b365d286fdacc0acd8988f8f2e023288f3a2ae2f9cbcd3d0ebcfcfb8930886087583cfa4c7e1450b984a7881aac3aea7a04cd3ca438520de2aab57340dd7d0e6edb598283c30090f87f3ecd98768e559d4881e33f2cf40c4b5a8052dbfb5489bb2e62af887e249b67737cafd13d6154b8fd0698e705ec5fc670ea64f1eb732f8d1f'),
    verifier_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('a48177347fd65ec55ebaf18a40e82292cfc9de91003dd9db2cfdceaf956ec3c1c096f8995d8b1f11800b20c5b62af5a4'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    L: 11,
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
  },
  output: true
}];
/* eslint-enable max-len */
