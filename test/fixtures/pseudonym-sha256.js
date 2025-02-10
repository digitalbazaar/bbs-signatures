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
  // FIXME: old below
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
