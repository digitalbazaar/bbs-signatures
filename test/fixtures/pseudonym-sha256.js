/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  COMMITTED_MESSAGES,
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
  proof_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_')
  }
};

BLS12381_SHA256.fixtures = [{
  name: 'valid no committed messages commitment with proof',
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
  name: 'valid multiple committed messages commitment with proof',
  operation: 'NymCommit',
  parameters: {
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    committed_messages: COMMITTED_MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: [
    // commitment_with_proof
    h2b('99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44'),
    // secret_prover_blind
    h2s('15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8')
  ]
}, {
  name: 'valid no prover committed messages, no signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('8e0595c93044ff2da97c466418ea0eb8648f1ed5cb040f90decb338810c5db168a464eacba02eb9dec7659920e59409a1faff9a30512ac66886db438787b463125e08e5aeaf4f4467a066dbd1520a984'),
    verified: true
  },
  debug: {
    B: h2b('806cd9006d8c4426821c51b6620b1bac7bb33bb349338883b1cf945d192c1013b3660641a777ee67adc14f04d568b761'),
    domain: h2b('728c2ba4c6e6a7b42c3e17c95bdf6ac83eacddd27a57dc681fbca0601c9fb317')
  }
}, {
  name: 'valid multi prover committed messages, no signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('b30fcb3c30a7eb5a864fadc88e2cdbce2b42bb9400b844a21e5d7ff0713f3cbdf1a082572247d447fb3848bc41dfc6d73840c7e56d0f869c4bee08aebc411e8b93b396734c96f26a4b7a708a403ff2c9'),
    verified: true
  },
  debug: {
    B: h2b('b8a96f809bf8bd7081461e4ce151e4951e68e2d3210a6f59a998ef84df0f6bfdf09ab0fd0015f72378549bb53b82c38e'),
    domain: h2b('1c63c8a9f1c732382f4803e13188d2e433a67afcd59913eeddb4082a3a832dad')
  }
}, {
  name: 'valid no prover committed messages, multiple signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('a8c362043de23de5331483e510aafca643d7d1ace1b50003f4cc0eb250868531d401e0d3af8a35dc596ef209f41b4f6f28f5c63f8a096e2a3072633fa624872c3f6f41fb5121b354ad7d0c0ea07e0f2f'),
    verified: true
  },
  debug: {
    B: h2b('a1abe3d14bd71b236c003fc1b69930dfa1cbe4f44db047bfddb5fd5c3b5a40b15c0ad364afce854089faa407a8cf8170'),
    domain: h2b('1336f81ac1181906aa77be751b7be985adb49616287ef2f1e4b8ac7771bb6195')
  }
}, {
  name: 'valid multiple signer and prover committed messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb621a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe34c00ca333a9006e769b4930e39210c8'),
    verified: true
  },
  debug: {
    B: h2b('91437a9b859b8623ef0990ea1b07fc6951338042565dd4f9c59f46d95eec8cf72db31aacba6b1b2c958c22c47ee238ae'),
    domain: h2b('4508e372d4ede742110dbcbc3e0c0d286f6d7388827b98805f7b62ad17678d93')
  }
}, {
  only: true,
  name: 'valid all prover committed messages and signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('99f409633ab1140121a94508a25d3ef7fe9d7da3559408502e81331f80cbddb621a99c02b6bab14c44aaf35b19006a1d0a91f0ac5a47b9c0a99a290c3f36debe34c00ca333a9006e769b4930e39210c8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487'),
    L: 10,
    disclosed_messages: MESSAGES.slice(),
    disclosed_indexes: [...MESSAGES.keys()],
    disclosed_committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [...COMMITTED_MESSAGES.keys()],
    // FIXME: add `H2G_HM2S_PSEUDONYM_` by default to pseudonym interfaces
    // and then retest
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('80c5bbf18019cab060588417725e00cb1b21aa86d79100af2c2cf90d6f2b8a042196bba6e686adaceebaad41a15ead368fbf593c7170044f4290d90484013c224c7104650e8eaa874f8456879988a403295aa6de5c6a00af182e68e5c01ab2ce8bbe372d8ec346fdd3c6cd07e857490b46c0169fa367286cda03204ef9a5615bfaabb50b47ab8ff77c87b890f400f49e10ada3b9b8add504356e8ec72ac512a20aa9b2f05e0dd58f409533d2157d36355d71d3458e86b39df14b591b8460f5784f9e7de26bebd3bb68d30a4a7baf55a84eda86f3d04aa375b988e550d81face6020808875ed84263f23252545ad66b2c2ea39d49d2fdeb716f67039bbb6e6e8899ebe394623be9508f3f850302fe0e530031541ba38a3a0aa195344002fbb453e065d22ce32ed9079baa4e553d31d0eb617597a06f858d771f98e38f1a708718b838e0e50fa5ad9ca8ef61284deb2b3c'),
    verified: true
  }
  // FIXME: add proof 002-007 fixtures
}];
/* eslint-enable max-len */
