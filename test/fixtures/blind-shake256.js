/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  COMMITTED_MESSAGES,
  h2b, h2s,
  MESSAGES,
  TEXT_ENCODER
} from './common.js';
import {CIPHERSUITES} from '../../lib/bbs/ciphersuites.js';

/* eslint-disable max-len */
export const BLS12381_SHAKE256 = {
  ciphersuite: CIPHERSUITES.BLS12381_SHAKE256,
  key_material: h2b('746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579'),
  key_info: h2b('746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e'),
  key_dst: h2b('4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f'),
  SK: h2s('2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079'),
  PK: h2b('92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5'),
  message_scalars: [
    h2s('1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f'),
    h2s('3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f'),
    h2s('6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94'),
    h2s('33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512'),
    h2s('52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471'),
    h2s('2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc'),
    h2s('0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3'),
    h2s('4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356'),
    h2s('1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650'),
    h2s('27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78')
  ],
  generators: [
    h2b('a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8'),
    h2b('903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e'),
    h2b('84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb'),
    h2b('b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93'),
    h2b('8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68'),
    h2b('990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140'),
    h2b('b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd'),
    h2b('b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e159b31c8d079c76a67321a30311975c706578d3a0ddc313b7'),
    h2b('8311492d43ec9182a5fc44a75419b09547e311251fe38b6864dc1e706e29446cb3ea4d501634eb13327245fd8a574f77'),
    h2b('ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc'),
    h2b('965a6c62451d4be6cb175dec39727dc665762673ee42bf0ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005')
  ],
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  commit_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_')
  },
  sign_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_'),
    count: 1
  },
  random_scalars: [
    h2s('1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083'),
    h2s('6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4'),
    h2s('05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306'),
    h2s('4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d'),
    h2s('5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51'),
    h2s('646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4'),
    h2s('363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4'),
    h2s('12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6'),
    h2s('513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a'),
    h2s('6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429')
  ]
};
// convert generator to points
BLS12381_SHAKE256.generators = BLS12381_SHAKE256.generators.map(
  g => BLS12381_SHAKE256.ciphersuite.octets_to_point_E1(g));
BLS12381_SHAKE256.generators.Q_1 = BLS12381_SHAKE256.generators[0];
BLS12381_SHAKE256.generators.H = BLS12381_SHAKE256.generators.slice(1);

BLS12381_SHAKE256.fixtures = [{
  name: 'No Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: [],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'BLIND_H2G_HM2S_'),
    mocked_random_scalars_options: {
      seed: BLS12381_SHAKE256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 2
    }
  },
  output: [
    // commitment_with_proof
    h2b('95a6f21801b2010a9016c590cd6f0d59682e908a46cdc9856eea2c5000545626fc755c13ce93a71e371b0ae05491326302a8e40b4fc1197d75c46d2114c711d9186e4af0498dab260ae56f81dbc59f7b2a9f4883479ce40e765a32b6481766ed5aeeddecd2decd277460a5e129a22934'),
    // secret_prover_blind
    h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249')
  ]
}, {
  name: 'Multiple Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: COMMITTED_MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'BLIND_H2G_HM2S_'),
    mocked_random_scalars_options: {
      seed: BLS12381_SHAKE256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 7
    }
  },
  output: [
    // commitment_with_proof
    h2b('a90a9c986623c7df72f1b55f885a7f25070d5b73178f7139fd6e948067e9f748b1cc0d4db3cbb9123a18851714ec9c161b678690dbd0ae67f4bac061bb80824ba208906d581586971c6a32e2a162eddf0ed4a8cc260f2cc9b505fd5ea078d21ae76159866c476cb129ad719511edbac763ec9b34c7943c520f598bacd7775e8345a9b3c2c2490fab27c97f1529ff319b4995ea15ff5e46ec26347d6a6bbf2e4b2a8da145f6afd5444464d86f79cd7df32fcc665b9245e138c752decfb3d507f2024af86b202741bf946e199ac77730a070821d7df69ce563d2d4142572431047dc6b544e4a8280ada8c3c01a2d3f454e4cf1dc293f09e6a5b743f275286ce601f28b1838441265c1c18b4425b8bd3d5c'),
    // secret_prover_blind
    h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649')
  ]
}, {
  name: 'No Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('95a6f21801b2010a9016c590cd6f0d59682e908a46cdc9856eea2c5000545626fc755c13ce93a71e371b0ae05491326302a8e40b4fc1197d75c46d2114c711d9186e4af0498dab260ae56f81dbc59f7b2a9f4883479ce40e765a32b6481766ed5aeeddecd2decd277460a5e129a22934'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    secret_prover_blind: h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHAKE256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('90c93d864fb857dc4290e1cb2f6c82973c2562b4bfb8edb61c2300da84b7d709733024c215acc0e224ee4b64ab5987d0312e84786009cece2aee01884b19c81a592aefb557f025fccdd8c67ca0a5d8c3'),
  debug: {
    B: h2b('b34e5cf13d77074c4762d92f98cc6b8c2567c816a2ea792d0f49263b8da314b5493830b78563fdb9e2abcab2a7a3c21f'),
    domain: h2b('41f87ee87af7a093831d77576c64d41e0d89bcd05ea6c9dd5be25bce3c728c55')
  }
}, {
  name: 'Multiple Prover Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('a90a9c986623c7df72f1b55f885a7f25070d5b73178f7139fd6e948067e9f748b1cc0d4db3cbb9123a18851714ec9c161b678690dbd0ae67f4bac061bb80824ba208906d581586971c6a32e2a162eddf0ed4a8cc260f2cc9b505fd5ea078d21ae76159866c476cb129ad719511edbac763ec9b34c7943c520f598bacd7775e8345a9b3c2c2490fab27c97f1529ff319b4995ea15ff5e46ec26347d6a6bbf2e4b2a8da145f6afd5444464d86f79cd7df32fcc665b9245e138c752decfb3d507f2024af86b202741bf946e199ac77730a070821d7df69ce563d2d4142572431047dc6b544e4a8280ada8c3c01a2d3f454e4cf1dc293f09e6a5b743f275286ce601f28b1838441265c1c18b4425b8bd3d5c'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHAKE256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('b788904003da89dc167016c3d58a296a145c411df7cc616cfeb79db8d07d5361210ef79599453acc7ee706d80e114be369ca4043e008ea4373e1d3d7bb60c11161d1d6d67ad23a808f0ce52677c724dd'),
  debug: {
    B: h2b('a537c41dd0dac2de5d21296e32e43f07b27e2ea4c1757247c36fdf7d5541d9e97a483e0b729a8b83638f15fba0cbda29'),
    domain: h2b('2ff95924f5218644c1a5d1722d815146e5b2c195d231421aea572e00527849d2')
  }
}, {
  name: 'No Prover Committed Messages, Multiple Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('95a6f21801b2010a9016c590cd6f0d59682e908a46cdc9856eea2c5000545626fc755c13ce93a71e371b0ae05491326302a8e40b4fc1197d75c46d2114c711d9186e4af0498dab260ae56f81dbc59f7b2a9f4883479ce40e765a32b6481766ed5aeeddecd2decd277460a5e129a22934'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    secret_prover_blind: h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHAKE256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('81d03e119cf3a1257a58b288c27132d0ec37e3695eb37ecc064094221baa4f9775483ed57227385659498480f8e92d8d28a9f576cbdc2f2613c68d6184598dc47d9c12cc94654072bd9ee708f72d02b5'),
  debug: {
    B: h2b('92c9bd227788c660f82397b7cadbebdcb83bfc4256362605caebd57849ca17371c5dd67af7b763f0c207eb73cd0d9d97'),
    domain: h2b('1561412ed694d0eb532e042ae2098fc999325394317c686ce94a84db29552100')
  }
}];
/* eslint-enable max-len */
