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
  // FIXME: remove `pid` if no longer used
  pid: h2b('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  commit_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_')
  },
  // FIXME: remove if no longer needed
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
  only: true,
  name: 'Nym commitment with proof',
  operation: 'NymCommit',
  parameters: {
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    committed_messages: [],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: [
    // commitment_with_proof
    h2b('b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b'),
    // secret_prover_blind
    h2s('3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041')
  ],
  debug: {
    s_tilde: h2s('3a3b481c984f4396a13b1f65368aa393d08455fbfd351ab80f593aa5de8b4b1d'),
    m_tildes: [
      h2s('5e82a40ae25e65fb04d7722f36ecd62fa4f07c8815e74f0a14a7e0a6547a36ce')
    ],
    C: h2b('b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c'),
    Cbar: h2b('af8152d30fc149adb48825795fc0bf51c509c584cb164a703252dd8857e6ffda60b1a82f1cd2277dff24dd002227bacf')
  }
}, {
  // FIXME: old below
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
    // FIXME: test fixture
    signature: h2b('ad5d4ff88f21c3995c5ffffe85c3cf12c1da9af6569f7cf498b59bb6bbcb792abd739abf28ecad3afc7f31f43c1c496c63a9a7b292fadf8d31045a70d700ef26fa83bc4f4c4cbb83d63934b5cb521c23'),
    // FIXME: adjusted adding signer_blind message
    //signature: h2b('b302996d200d0d1b2c33cb6e3850c29d8adc45611940d5a3cf41ade6d73f540b4704fe0a8c187a75f855606ab298c5065d8bba2dd9ff1ace41b1d611f7300bcfedba0fb21dd0ff43ff1a8de855ad0501'),
    verified: true
  },
  debug: {
    B: h2b('b822ddc4e5f6f7e6926322c1b973614fc93366eb0eafb7de44c72a2b5cd8109f61c698d42c959aac590c6e05b74b5b1e'),
    domain: h2b('4e81a5edde18cd1368634f05b596ac9965d06981f8e9c21d2272593883852603')
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
    // FIXME: test fixture
    signature: h2b('ad5d4ff88f21c3995c5ffffe85c3cf12c1da9af6569f7cf498b59bb6bbcb792abd739abf28ecad3afc7f31f43c1c496c63a9a7b292fadf8d31045a70d700ef26fa83bc4f4c4cbb83d63934b5cb521c23'),
    // FIXME: adjusted adding signer_blind message
    //signature: h2b('b302996d200d0d1b2c33cb6e3850c29d8adc45611940d5a3cf41ade6d73f540b4704fe0a8c187a75f855606ab298c5065d8bba2dd9ff1ace41b1d611f7300bcfedba0fb21dd0ff43ff1a8de855ad0501'),
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
      count: 13
    }
  },
  // FIXME: fixture w/ blind generator
  //output: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2abb8ca4d57b79d632df956fbdad0a803ca1952077c70b3b028bae10d5c9f3f8aec51db8782f24437ed93ae6ee020ffaea22a52d03abaaf3e0bf1cd374e7d9bbcbcbd3118b2086bcacd28298a8b277fdd78b5635ae3a153ee3b9c85edfa43428f32a85998a04ad67d77c9568bf674013d319ae80094eaf384d153e5f5776b0b1433d6b6c33eba9aa432036cd2b25479bb1313300e91ed3eb982af3b39bac0236d55dd13116bda2ff74d5b4299f211404e55e0a861b789ea758b47ca5c9e13af4d0fdb2ddb82e9d15f7b74a96d2d901ab43ff3c29266e2761110455b213550a3fa3f7fe54281a6b6db5e173d75ad7315b68d34c0284575cfbffabfbc5d6a1a802246cc7ff356cbc88543dd5320575d5435aba4d0b9bea49507d84d3813d34ee5ad64609c03f941ac2c2419917d7242170ed20aacc88ec38b8d2176cad9a8f911c2529f7319fc8e177c51b74748d583a8a78c46a6f1f4c485385c00b8941b6309b0613b4dbf0be8837d7124c73825b49a86d49106b9132c3db9ad6e0aad47d8dfc41d5a522f0baae2943d95bacdd05c2ab82d8772412b00dc2fffec424a63054cf2370ea5d3fc3d689e8b3bcb12d8869f3948654616065c59962f413fe2a59daa25')
  // FIXME: fixture w/o blind generator
  //output: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2938b9d384a866a8f9bfee7981d893f9e5a4a3c22a9dc57e65e2ebce7bc5aa856b845b11fe69a97c11e82e0d710c84c8dadf182b16ec437ad26105ba1ecd9b08b52d4bddbc7b2436f6e1e1f086c76262feee24f78d2a3ec5a304b7243a7a3559b48c89257f83e44a1704db13094a8f462bc2b05407b7e8b53cd43ede7a004e3ea5fe272d55a4419f0b5120e2bb5354d04ae4326b42dd5bb385d20202a4be7ea6e73987e4aab6bb1bdecc46bef8cfe6eddbb46bb932656c967345d4a6431e6c31940ae42e6376c0d6ef0294c93a68c5665b907cdb167ebdb64de87fc5df13967535983a4f052990334cb5a855b46c26ab3e7b78e4e6e6b6b38d52d49f18a5517d02041c89d73f15c048a52e19a319d4cb04ccf9d68e9f3c7597cf614363fb9da4d5c8a98b67e026a5e83cbdc208a1d68b72b0dea1b79c8c4e088a2286796014b365d286fdacc0acd8988f8f2e023288f3a2ae2f9cbcd3d0ebcfcfb8930886087583cfa4c7e1450b984a7881aac3aea7a04cd3ca438520de2aab57340dd7d0e6edb598283c30090f87f3ecd98768e559d4881e33f2cf40c4b5a8052dbfb5489bb2e62af887e249b67737cafd13d6154b8fd0698e705ec5fc670ea64f1eb732f8d1f')
  // FIXME: fixture w/o blind generator + extra generator
  //output: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2a46c4754556ac75539b011dd5fa122304d3b48983ce58df26f3f5f9bf59e1688a5f09211e209f9190adedf5df1060568b16842ec612d9f6596202073938e0651d183b33fd2f7cf8b9cb4186edc5637a1b33c7de1c2d7296c546ad2b0cc0ba4ba2617966fa82e87d95bb4016566b0122556ac81b1ddde4a1698f203cf2395f13a6d3f41c3d13919991e9549b951e96160c0d042986099a6f6e7b793730888c80a48a67aa90a4b759d24a96a3518f5c964448e83fefa713c370c19231ed876fd0644411c9a5df063f112048de2740dbc308aa75c5db236dbd603421c1badfbdcb13b2a48fde52c6e2596fd866ada8164a748d18ae51cf95b5a9bc43db06c46630a2bf37da7b2221f2ecf5fd36cca4fadb0bda3c4cb81889d8d377aae6c805487cf6fba572e32f1a52f6ec4e20c648cdecc2aaa644208fe0e703401f2e1c16ed2de5bcc799eea8d464eb822ebc03f1621e32682f33edacee9ff9ccd066a935ea0813b3db5e2aaa3f5ee2038c1eb1cec50dc2f83bb1566715ffc01f79af2436e8d974423b3a613ff3949fc2300096aa4d0f96555d61c3022ad3ef89f93bd8e31ae1c6bfaee4b16be54acf39c0b1ba0d0edc440b30f528d5ebe9e5ce8580d634b4a80')
  // FIXME: fixture w/ blind generator + blind_factor `0` message
  output: h2b('916c5c458decd51aacaa3349f2e6bae5139448ed65d6435d06c31b0be41bf274022ed36ed6b75f23e5dae0f17f8f12c7b7fad4d8ded2da5ac519809bcb535174303e42eb7d596672b7bd1dc214a67d4b514be2f547b2c2e9c9adb805e6bb803082e0ccaff1487087c9a3545f7d790ec7652db866624246b5448e32b47ada85204fed3fc516cac44fe17f9612670346d655974f4676d7d5c90ac8dcd98bde88777dccf577b9ea43ccb4fd6d62080451e903a2759154c04bfe7ab73934c62c8a12b3f3db6f1c8fbc5f7c17882ad747f3c2589cf6cb015a6da1fd18f5b2280db3ad29bdceba8d5c3edeb937ac7f40e803f56ebdb57dcb602287a0cd7e3b5fbf888a1357257dab9ad27fc5785248bfe2769b67b8a5daefa7ceb828cfd2b3e2c66bf5b4fa14609cad53b1919b3f5cd5e83346375b4f38d6a9a3a163659c5a8fcaffc6889a3b32d1cbd0320fbac6074e30ca2c6c7e81e8e658f33b88cd72934c605579841dee4ece1a059e038f7d2b75a39940613b64845eddb04f6cf969143044a7b2dd196284fc154f202a04fff670d1ebc137f271ce12052b54e78be75e6c30a62d46c58d666714be82d9880ed4b639e3e055a0c02ac768d6dd502a9c52c61d3285d578064b24755cfe7711902b3bd463854c583e5e4fc913aa71989afc50cfd8c2024d64df96ed12c7ef82d50ed4d8bb1b429f1c281e27ea4472637371c5908621b1dbf2eeac1accda29b8cb5ee6352b27')
}, {
  name: 'Valid multi-message signature, multiple messages revealed proof',
  operation: 'ProofVerifyWithPseudonym',
  parameters: {
    PK: BLS12381_SHA256.PK,
    // FIXME: fixture w/ blind generator
    //proof: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2abb8ca4d57b79d632df956fbdad0a803ca1952077c70b3b028bae10d5c9f3f8aec51db8782f24437ed93ae6ee020ffaea22a52d03abaaf3e0bf1cd374e7d9bbcbcbd3118b2086bcacd28298a8b277fdd78b5635ae3a153ee3b9c85edfa43428f32a85998a04ad67d77c9568bf674013d319ae80094eaf384d153e5f5776b0b1433d6b6c33eba9aa432036cd2b25479bb1313300e91ed3eb982af3b39bac0236d55dd13116bda2ff74d5b4299f211404e55e0a861b789ea758b47ca5c9e13af4d0fdb2ddb82e9d15f7b74a96d2d901ab43ff3c29266e2761110455b213550a3fa3f7fe54281a6b6db5e173d75ad7315b68d34c0284575cfbffabfbc5d6a1a802246cc7ff356cbc88543dd5320575d5435aba4d0b9bea49507d84d3813d34ee5ad64609c03f941ac2c2419917d7242170ed20aacc88ec38b8d2176cad9a8f911c2529f7319fc8e177c51b74748d583a8a78c46a6f1f4c485385c00b8941b6309b0613b4dbf0be8837d7124c73825b49a86d49106b9132c3db9ad6e0aad47d8dfc41d5a522f0baae2943d95bacdd05c2ab82d8772412b00dc2fffec424a63054cf2370ea5d3fc3d689e8b3bcb12d8869f3948654616065c59962f413fe2a59daa25'),
    // FIXME: fixture w/o blind generator
    //proof: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2938b9d384a866a8f9bfee7981d893f9e5a4a3c22a9dc57e65e2ebce7bc5aa856b845b11fe69a97c11e82e0d710c84c8dadf182b16ec437ad26105ba1ecd9b08b52d4bddbc7b2436f6e1e1f086c76262feee24f78d2a3ec5a304b7243a7a3559b48c89257f83e44a1704db13094a8f462bc2b05407b7e8b53cd43ede7a004e3ea5fe272d55a4419f0b5120e2bb5354d04ae4326b42dd5bb385d20202a4be7ea6e73987e4aab6bb1bdecc46bef8cfe6eddbb46bb932656c967345d4a6431e6c31940ae42e6376c0d6ef0294c93a68c5665b907cdb167ebdb64de87fc5df13967535983a4f052990334cb5a855b46c26ab3e7b78e4e6e6b6b38d52d49f18a5517d02041c89d73f15c048a52e19a319d4cb04ccf9d68e9f3c7597cf614363fb9da4d5c8a98b67e026a5e83cbdc208a1d68b72b0dea1b79c8c4e088a2286796014b365d286fdacc0acd8988f8f2e023288f3a2ae2f9cbcd3d0ebcfcfb8930886087583cfa4c7e1450b984a7881aac3aea7a04cd3ca438520de2aab57340dd7d0e6edb598283c30090f87f3ecd98768e559d4881e33f2cf40c4b5a8052dbfb5489bb2e62af887e249b67737cafd13d6154b8fd0698e705ec5fc670ea64f1eb732f8d1f'),
    // FIXME: fixture w/o blind generator + extra generator
    //proof: h2b('b842263b0948604f224f7fa512aa28adb84747e55cf1fb68c1fe1df935a7baf549f272fa960f108e5700b11607aeb0d2a46c4754556ac75539b011dd5fa122304d3b48983ce58df26f3f5f9bf59e1688a5f09211e209f9190adedf5df1060568b16842ec612d9f6596202073938e0651d183b33fd2f7cf8b9cb4186edc5637a1b33c7de1c2d7296c546ad2b0cc0ba4ba2617966fa82e87d95bb4016566b0122556ac81b1ddde4a1698f203cf2395f13a6d3f41c3d13919991e9549b951e96160c0d042986099a6f6e7b793730888c80a48a67aa90a4b759d24a96a3518f5c964448e83fefa713c370c19231ed876fd0644411c9a5df063f112048de2740dbc308aa75c5db236dbd603421c1badfbdcb13b2a48fde52c6e2596fd866ada8164a748d18ae51cf95b5a9bc43db06c46630a2bf37da7b2221f2ecf5fd36cca4fadb0bda3c4cb81889d8d377aae6c805487cf6fba572e32f1a52f6ec4e20c648cdecc2aaa644208fe0e703401f2e1c16ed2de5bcc799eea8d464eb822ebc03f1621e32682f33edacee9ff9ccd066a935ea0813b3db5e2aaa3f5ee2038c1eb1cec50dc2f83bb1566715ffc01f79af2436e8d974423b3a613ff3949fc2300096aa4d0f96555d61c3022ad3ef89f93bd8e31ae1c6bfaee4b16be54acf39c0b1ba0d0edc440b30f528d5ebe9e5ce8580d634b4a80'),
    // FIXME: fixture w/ blind generator + blind_factor `0` message
    proof: h2b('916c5c458decd51aacaa3349f2e6bae5139448ed65d6435d06c31b0be41bf274022ed36ed6b75f23e5dae0f17f8f12c7b7fad4d8ded2da5ac519809bcb535174303e42eb7d596672b7bd1dc214a67d4b514be2f547b2c2e9c9adb805e6bb803082e0ccaff1487087c9a3545f7d790ec7652db866624246b5448e32b47ada85204fed3fc516cac44fe17f9612670346d655974f4676d7d5c90ac8dcd98bde88777dccf577b9ea43ccb4fd6d62080451e903a2759154c04bfe7ab73934c62c8a12b3f3db6f1c8fbc5f7c17882ad747f3c2589cf6cb015a6da1fd18f5b2280db3ad29bdceba8d5c3edeb937ac7f40e803f56ebdb57dcb602287a0cd7e3b5fbf888a1357257dab9ad27fc5785248bfe2769b67b8a5daefa7ceb828cfd2b3e2c66bf5b4fa14609cad53b1919b3f5cd5e83346375b4f38d6a9a3a163659c5a8fcaffc6889a3b32d1cbd0320fbac6074e30ca2c6c7e81e8e658f33b88cd72934c605579841dee4ece1a059e038f7d2b75a39940613b64845eddb04f6cf969143044a7b2dd196284fc154f202a04fff670d1ebc137f271ce12052b54e78be75e6c30a62d46c58d666714be82d9880ed4b639e3e055a0c02ac768d6dd502a9c52c61d3285d578064b24755cfe7711902b3bd463854c583e5e4fc913aa71989afc50cfd8c2024d64df96ed12c7ef82d50ed4d8bb1b429f1c281e27ea4472637371c5908621b1dbf2eeac1accda29b8cb5ee6352b27'),
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
  output: true,
  debug: {
    B: h2b('b822ddc4e5f6f7e6926322c1b973614fc93366eb0eafb7de44c72a2b5cd8109f61c698d42c959aac590c6e05b74b5b1e'),
    domain: h2b('4e81a5edde18cd1368634f05b596ac9965d06981f8e9c21d2272593883852603')
  }
}];
/* eslint-enable max-len */
