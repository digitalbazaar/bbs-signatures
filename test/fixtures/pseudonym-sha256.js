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
}, {
  only: true,
  name: 'valid half prover committed messages and all signer messages revealed proof',
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
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_commitment_indexes: [0, 2, 4],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('b3609d5604e27ef07ed771fbe781640c4945f65626c1ec447e836ae27914cccf69c91817af6a29d32d83c895540c9cf1b959e4cc8e689ab3b3f8b2247cd4be9e82cc19af253ed1785ca1a34a97267f9d301539d1f7f204816d7b91e8e32ab82ea30a03cf553a9c598db24b5a1da8b69aadb79e0a942321c1621035cd6d275b688a5a18fe740d3e1ef58f50819940cb963ce17df31e0f03dc5d326bbbe07724468f3d4f693a70a98cb7cbe6bd7596c7bf592b58a7f2bf640a673d33d669a528a20475befc50bf69bdf78160cac32a3521419dec99be743e27d975fff7077e322cb163d4088be7492c3c7e2104bdaac0a84597622aac2f1c5d85fa9f199fc562c001c01ac9ad614827bbd0b2d43602c2bb6d722fb78212e9d169252f7ad85f77e043f6cb9acf117308a7b2e8d03a77ceba4bee9a1fb735ca38048dc9a98c54d3bd3413b45223c59e15afb0c26f01ff66f137179d0006e1584323581974b75cb78493c87ffe12f432d7ed812fc95424a8c24635c8a4a27781a120bf80df9db922f9ca1ad13da46a49bb0094847603083b63'),
    verified: true
  }
}, {
  only: true,
  name: 'valid all prover committed messages and half signer messages revealed proof',
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
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6],
      MESSAGES[8]
    ],
    disclosed_indexes: [0, 2, 4, 6, 8],
    disclosed_committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [...COMMITTED_MESSAGES.keys()],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('9862cf4d03193c24f13781a02394df3f7b9ce04511592f4b8a1ec0e24331397ba967ea5bf1053b99f1c82e6e0351e1d0b7934c1a1d935eb89de7b45c427f0a550b9432d0a58f594098ba0f8f470f9f2e4c8b4a50736d3b51d3810fa18d4b343883e607bcc4bdc4e76a5b39161ca96391354facdfa4fa47cc5b0fe1bd91768f20139e599d4ee9bbc231bf3044cf2385d768b0ebf68e5ce4d8cc846fb7c6bd8f641e44a68170462ce0d5204045544c60a5183b0116de517928cb1aadb5e59c89c8a77bc0df77de9fb1134d66ca9454f0cf603952748fd41c40dbaa4d9ef1b309804ec7f158db099fcd0c7866b6b3336ff3406ea07011efa8af032b60ab5e93baa20db28a5b31478ebbd9440f33d69028a23339683c120fdd978369b26d05a2a029c76f5277fb058431623a2c9be517ba4b619c942be097ddf277c9884aa3fc9faae80f3dafaa2ad535721c247760838a603842da75da3ba276344f4cf0713c91b76df021356e667db02b70f714ab71d966664d9e679f1527473a3ffa9c930782a8f349b8dceade0fb6b8121a276ab689fe5330cf4e6d5650b13ac4a8ab4930da894f94d2dae09fc94e664dd8490fee8a7d5a7dd52f10f88c828d7ea137fb95103edd7cc5497ed3e98bc2c6582e34234d2131328cfa0e1e39db013c0988dcf4978c866c1e757c67e9a729d308ca22ed8f0d'),
    verified: true
  }
}, {
  only: true,
  name: 'valid half prover committed messages and half signer messages revealed proof',
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
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6],
      MESSAGES[8]
    ],
    disclosed_indexes: [0, 2, 4, 6, 8],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_commitment_indexes: [0, 2, 4],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('8a62e1920818e649ed51e28aacf1eb069dc06817882b6c5018801c3acfff44a6d311ec93ba167ad6538de41aa08f8b37970916033aefb249f7d458f9e10f63031cb1c45cc64b094d07dd4cac6b2341b31a454581ae68b59eb7fc56cfac702ff792abc5535f3fc5db8e0765fb902d648b64d8640d6bb53f09553ba8c1e125de902abf7a3aa01b541e0a97c2895fc452570bd08e5b513b1d416c3c43b8817688b906b67c7eab1e39bdcd1f72159c657bc15252e9747d127ec276a560cf51df9d56d595a27a804dd219dc202afe946a14543f44ef35f10dc02e00264b590af5a4dbd2271eaf67d6701aac36f781d7278e321d023d8ef84426176b3aa6b142e18cbe0dd4b66fd1b740d700b38f48714aaa7857bcb869dbc53971c58ae9f521005a6d73b4cd6b86a4e75af543477dc16fb9685145d1c847a8912577bbfd5367a5d9dce109b5b50e30a58a4ba349afe98183730fdbf9baeeda7efb9c2592d33c6a06294b048c9c7ae97f5e53610399c57385aa0afb15864255c6891a72c3e668afd970bc832694c6faff88ede68b04932b28914bdfa291bf16a7426528b25f4f2df26c2816a341ab3c5473a42ed5d54b91c16a0a4c16b3556a768fe0b33de2e06fe4d0d634746d1bed19363c9d1b779e1b39b846d660b16c66baa30b377800b3cbecde0a2a96a6672af4dd6178c24e1396ead043bd37eaeb27e027c18581a523ad9cc311cab68b972b7143eecaa519c81499402748906732822a82890eb57f7561c8b5db183574eff0fafc91eb05ca80072e1d'),
    verified: true
  }
}, {
  only: true,
  name: 'valid no prover committed messages and half signer messages revealed proof',
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
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6],
      MESSAGES[8]
    ],
    disclosed_indexes: [0, 2, 4, 6, 8],
    disclosed_committed_messages: [],
    disclosed_commitment_indexes: [],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('add3221aa11a1857cc7a42ca1a92275f4ce564f0914b181751c5a900fd4f8995e72ec98b9033758cbc33761549ed0b538e711dc3d91b28d4309648731ad9c74915ffa9c17ded7f4df05ca10c0c44adaa4d5b945f6d008692cd14bdd59ea012ef84460c9e82eaa6b55f48b0a2c3a437e72b96c568716df6fc4dcf9cce56b7ddc8fcc7dbcec9090ef6794e861dc8f7fea255707d38665a55aa3b6d177d4282b81ed0b93367dd6208700a0207abe13593d1288974c28380354320a1e73fa5fb974618d5a852a5e5deb3e06afe3bc82315a73dc4917f064a21eed9f702932588254fbed51202cc1fc0a38ca42c243816ca2b6dfefd7c76dcfad9321c1907371b78bef1fccd5e42be16d36757f2c0f6ef15f52ac81bd46499410f75bca592b750aa596c07ca4fd6bd244c9d321f9422e8c15d504cd6614df24c75854030793c703dafa917e24162a4ca6aef0826597c3ba41c1586b1971334fc632f83505fc7dd12641aa603260b1425d896d6f363bd61ef732dc56aaf64ae6d55047dc52bf73c138161c16a46f995b20999a53599a48bb1ba734a3be4f4dfe1c9ff81efec2d4970a0b800de0ffcbbf209c83c55c462b756d9200bbf2ccb5d007daaa344067037f525c63d5fa8ef51ac2d2fc7f0b380cfbd2c29996b8add5333b467b4505973ba289a5d10efa4bc8ca51933ba48b16d82977f43c19bda9aff9a963d12e6a1bf07357590d49d23de780ce9486c5103d25682f32931aaaa162ed80b9066eb60125c33e191793c910f1557f9790ffddbaea850d42e510b4661b3038ed606e59452ec83187b88af9488ebf83797ace665449acd054471790c1fe9a37bc23aa50b3dde7fe24c2de1955fda7ddcb8dfb62baf91db20373282dd627ee2b2dd2595deb4b502e0d8c319f49a47464ba97e6de55adc99d1'),
    verified: true
  }
}, {
  only: true,
  name: 'valid half prover committed messages and no signer messages revealed proof',
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
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_commitment_indexes: [0, 2, 4],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('a95d0c2f1e89fa4f4049f45ecc89fa8a82589f296657ae2f1b50b73af04e251d97b4822566f24c04b52bdb3c230b540ea55f4db83a932a5803a29573e1a37705a1fa5a8bc59d3bc4e2f2e2bb39471ae191acf4e6738c3d962171dcb16d81063b88b4b9f2b517d1b428806e01b1fd245631e668cbabbe4d4a7d6ca7b6b60fdbc7f234e4b158e41ce72702c8586e260ee42f92cafb6f46f584b11d9ac0cc12d6e03727ea8f9ef0cdfc6c9d179ce0a8d1042d403a80bd935645cfceb09c455d1c27e1e563489f501482c969710077e49a2e4096157ba62f966f3314d4cdc23f67758a9e6e302e4dda34a6900067415e05f626644cd91fa518243deafe3ea3dd113413729b66f3a3aadd7f6a417428609847077a7495d2fb0bd5c54b8733bf735d876e3f70e46db442c6307829ea4f7229360de17e0ab31c82491cba75560a2bc16859f70f48647f28c3805240924f256b4e7234c8e83b8c569f3fbac04e6157effa690240f38d611ecb61354e2d7ec0870a36da985dabad7847f8939cb91f7dedb3601cec88af2169ff03668f0f381a20bd0e9dbe69cda97561279731e2b04d8fc0d48c9a92ad1f2b857b1bbf6d50ae8a6441ba5eb50c85ed05a3c6eaf00af0f8a8ce2b9f4d4a06d3cff8a243fd11652dd94176236d55d2d390936b15f676f819181cc2d73f77682db9cc06b9b14a411ce0375c56eb49ef752459c02dc8c065c3f5a8d795497e93a1ab59ae55a5505caec8515efb86c055331b1d8a31ec0fc181085c1e1ba1ee6df93c32af3f6930814a2552602f381fc24754beb43c9ca9c931ecc7a4c31220970ec805f604c01ed651f1166a583823774ccd6088d1be3b6af9f42b63178c7d1a5b70196421fbbdc5fb36238c8bbd6bd4cf886036d95abb86e4e7158e87813a5f9ba95df0e853964f4e040c663fcd0c745e54e0c939b8de61176d6d474fca6952dc0fd3720600e525038f32469e79368ded96f86056d48fdd9850ae1dcf7de039024b8940750c8f68d593'),
    verified: true
  }
}, {
  only: true,
  name: 'valid no prover committed messages and no signer messages revealed proof',
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
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [],
    disclosed_commitment_indexes: [],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_PSEUDONYM_'),
    mocked_random_scalars_options:
      BLS12381_SHA256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('8a088a3619f2be6061e47e93048b0ea5391e54a8e551e6064f8065e0f09db7be36dacfb2349797d889b9c456a07d0df5b93e0792af6d74293aac66b6be0902cddab66c1fce327d2690323d6083a80153969a46c2c3f3462fecb3d47fb6c9b909aea8b5cfbebe68f0b88f4e5718ea1a307eb84887e8a28b07cc1ab76f3ba34a9c81a9fa1ad7c2a59dff8b9fd993270ed63cc4723517f556b1657220c7b7e3946d88aaaccd7620eaeb0d52fa272bd2cd871c74d9a5a2ea52d2c4cb309fb267a8315eecb02a37906ae71cf47c50267f198806700d239566921e7b2ae7461fb6f2c1028702469ada2358c769ac5bbe79d3762adcc226be4f743984d8c2dffb27d7eac58fca920dead9129da6b4ced872e60d5d83b93c38a0d2b51b58967ffb8fa0cb904346755f84969e583ec69d697806d0492180385da37acf8640160c60f82d283ea0bd23f47362af5eeb1bbbc0c8d8d942a1647d78d787105d49b9493d912522d384e1ddd71ba917cf8eda4a8f2651fe33e9466d024a9771a4288bd0690e07d8dda9dce39b81ebca66509fc4a5990d4639f6d1f8cfd949d2090eda44d55e43563a33ff0371d4ed7ca039c65064f2b5d957d60baf654f6c2afaf8b49d1933d607d667b77e896ffdfeb1f6572dc6999f1a1ea753e05445a16000c237f762e9cfecba5f43fc65f126e1ed0d31c7855115540ab6c54ad8f321bc0428b998e52eb77eb5ddcd363a7eb4846d8ca820673d0e40447a71b207badeb394d7037fbce0c30eb50c6d2cde0f5fc1212fb6be8ed392e4448c278d7afc6992a4cbab933429a5f87e372b0ef6d11439862796fb130cc1d1621785848ae5512894ed4e97f87a1a1a85c0fe5ea8ed7e6ceabedc26c935266106cf619410fea374f4ba9604d01ce60ef4dfd25962b3174d007d997b9ef7c8120111a9a040d7cf4ef178da51d74627cda2cfb52ee6c33c3584bc37e7d89d727a02fbb2ab1639e5c5355c2233112d49bc48ef30e09f11a9933feeb936d26635af0445eb7eafdac863378175b936461a7183d848406b788f42c2dead4d419e51f150a7dc72cb46987b2444321a0ce9bc090fd936aa1f27dd3dffe3a8c5d490e96924d132773d7773051b9d594aa059a4793902948cf5ef5743e8865bf7cb320ada'),
    verified: true
  }
}];
/* eslint-enable max-len */
