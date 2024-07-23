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
  dst: h2b('4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f'),
  message_scalars: [
    h2s('1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430'),
    h2s('154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952'),
    h2s('0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22'),
    h2s('4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888'),
    h2s('34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e'),
    h2s('4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08'),
    h2s('064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743'),
    h2s('34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02'),
    h2s('57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74'),
    h2s('08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16')
  ],
  generators: [
    h2b('a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be'),
    h2b('98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4'),
    h2b('a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a'),
    h2b('b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62'),
    h2b('ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035'),
    h2b('b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335'),
    h2b('8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39'),
    h2b('abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1'),
    h2b('80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17'),
    h2b('82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f'),
    h2b('a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca')
  ],
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  random_scalars: [
    h2s('04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f'),
    h2s('5d87c1ba64c320ad601d227a1b74188a41a100325cecf00223729863966392b1'),
    h2s('0444607600ac70482e9c983b4b063214080b9e808300aa4cc02a91b3a92858fe'),
    h2s('548cd11eae4318e88cda10b4cd31ae29d41c3a0b057196ee9cf3a69d471e4e94'),
    h2s('2264b06a08638b69b4627756a62f08e0dc4d8240c1b974c9c7db779a769892f4'),
    h2s('4d99352986a9f8978b93485d21525244b21b396cf61f1d71f7c48e3fbc970a42'),
    h2s('5ed8be91662386243a6771fbdd2c627de31a44220e8d6f745bad5d99821a4880'),
    h2s('62ff1734b939ddd87beeb37a7bbcafa0a274cbc1b07384198f0e88398272208d'),
    h2s('05c2a0af016df58e844db8944082dcaf434de1b1e2e7136ec8a99b939b716223'),
    h2s('485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663')
  ]
};
// convert generator to points
BLS12381_SHA256.generators = BLS12381_SHA256.generators.map(
  g => BLS12381_SHA256.ciphersuite.octets_to_point_E1(g));
BLS12381_SHA256.generators.Q_1 = BLS12381_SHA256.generators[0];
BLS12381_SHA256.generators.H = BLS12381_SHA256.generators.slice(1);

BLS12381_SHA256.fixtures = [{
  name: 'Message Generators',
  operation: 'create_generators',
  parameters: {
    count: MESSAGES.length + 1,
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_'),
    // must compress points to match test vectors
    compress: true
  },
  output: BLS12381_SHA256.generators
}, {
  name: 'Message Scalars',
  operation: 'messages_to_scalars',
  parameters: {
    messages: MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_')
  },
  output: BLS12381_SHA256.message_scalars
}, {
  name: 'Random Scalars',
  operation: 'mocked_calculate_random_scalars',
  parameters: {
    count: BLS12381_SHA256.random_scalars.length,
    ...BLS12381_SHA256.mocked_random_scalars_options
  },
  output: BLS12381_SHA256.random_scalars
}, {
  name: 'Valid Single Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]]
  },
  // signature
  output: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
  debug: {
    B: h2b('92d264aed02bf23de022ebe778c4f929fddf829f504e451d011ed89a313b8167ac947332e1648157ceffc6e6e41ab255'),
    domain: h2b('25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c'),
  }
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES,
  },
  // signature
  output: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
  debug: {
    B: h2b('84f48376f7df6af40bc329cf484cdbfd0b19d0b326fccab4e9d8f00d1dbcf48139d498b19667f203cf8a1d1f8340c522'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'No Header Valid Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b(''),
    messages: MESSAGES
  },
  // signature
  output: h2b('8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d'),
  debug: {
    B: h2b('98e38eadb6a2232cf91f41861089cda14d7e3ddef0c6eaba4d11a2732f66408f394d58301ffcc8fcfb3c89bb75136f61'),
    domain: h2b('41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7'),
  }
}, {
  name: 'Valid Single Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
    messages: [MESSAGES[0]]
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b(''),
    signature: h2b('8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'Modified Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
  debug: {
    random_scalars: {
      r1: h2s('60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337'),
      r2: h2s('2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811'),
      e_tilde: h2s('6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd'),
      r1_tilde: h2s('0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8'),
      r3_tilde: h2s('639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1'),
      m_tilde_scalars: []
    },
    T1: h2b('a862fa5d3ab4c264c22b8a02636fd4030e8b14ac20dee14e08fdb6cfc445432c08abb49ec111c1eb9d90abef50134a60'),
    T2: h2b('ab9543a6b04303e997621d3d5cbd85924e7e69da498a2a9e9d3a8b01f39259c9c5920bd530de1d3b0afb99eb0c549d5a'),
    domain: h2b('25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c'),
    // proof details
    Abar: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194'),
    Bbar: h2b('a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aad'),
    D: h2b('aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a'),
    eHat: h2s('0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd656'),
    r1Hat: h2s('67373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b3'),
    r3Hat: h2s('3833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070'),
    challenge: h2s('32381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('9881efa96b2411626d490e399eb1c06badf23c2c0760bd403f50f45a6b470c5a9dbeef53a27916f2f165085a3878f1f4'),
    T2: h2b('b9f8cf9271d10a04ae7116ad021f4b69c435d20a5af10ddd8f5b1ec6b9b8b91605aca76a140241784b7f161e21dfc3e7'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a'),
  debug: {
    random_scalars: {
      r1: h2s('44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457'),
      r2: h2s('6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8'),
      e_tilde: h2s('721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081'),
      r1_tilde: h2s('1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f'),
      r3_tilde: h2s('0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e'),
      m_tilde_scalars: [
        h2s('7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4'),
        h2s('67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870'),
        h2s('715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137'),
        h2s('4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4'),
        h2s('438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415'),
        h2s('602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121')
      ]
    },
    T1: h2b('84719c2b5bb275ee74913dbf95fb9054f690c8e4035f1259e184e9024544bc4bbea9c244e7897f9db7c82b7b14b27d28'),
    T2: h2b('8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('81925c2e525d9fbb0ba95b438b5a13fff5874c7c0515c193628d7d143ddc3bb487771ad73658895997a88dd5b254ed29abc019bfca62c09b8dafb37e5f09b1d380e084ec3623d071ec38d6b8602af93aa0ddbada307c9309cca86be16db53dc7ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db3675ff70ce9006d166fd813a81b448a632216521c864594f3f92965974914992f8d1845230915b11680cf44b25886c5670904ac2d88255c8c31aea7b072e9c4eb7e4c3fdd38836ae9d2e9fa271c8d9fd42f669a9938aeeba9d8ae613bf11f489ce947616f5cbaee95511dfaa5c73d85e4ddd2f29340f821dc2fb40db3eae5f5bc08467eb195e38d7d436b63e556ea653168282a23b53d5792a107f85b1203f82aab46f6940650760e5b320261ffc0ca5f15917b51e7d2ad4bcbec94de792e229db663abff23af392a5e73ce115c27e8492ec24a0815091c69874dbd9dae2d2eed000810c748a798a78a804a39034c6e745cee455812cc982eea7105948b2cb55b82278a77237fcbec4748e2d2255af0994dd09dba8ac60515a39b24632a2c1c840c4a70506add5b2eb0be9ff66e3ea8deae666f198edfbb1391c6834e6df4f1026d'),
  debug: {
    domain: h2b('41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7'),
    challenge: h2s('4a70506add5b2eb0be9ff66e3ea8deae666f198edfbb1391c6834e6df4f1026d')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac48135672556358e78b5398f1a547a2a98dfe16230f244ba742dea737e4f810b4d94e03ac068ef840aaadf12b2ed51d3fb774c2a0a620019fd1f39c52c6f89a0e6067e3039413a91129791b2af215a82ad2356b6bc305c1d7a828fe519619dd026eaaf07ea81cee52b21aab3e8320519bf37c2bb228a8b580f899d84327bdc5e84a66000e8bac17d2fa039bb2246c8eacc623ccd9eb26e184a96a9e3a6702e1dbafe194772394b05251f72bcd2d20f542b15b2406f899791f6f285c7b469e7c7b9624147f305c38c903273a949f6e85b9774aeeccfafa432e2cdd7c8f97d1687741ed30d725444428dd87d9884711d9a46baaf0c04b03a2a228b7033be0841880134b03b15f698756eca5f37503a0411a9586d3027a8b8b9118e95a9949b2719e85e4a669d9e4b7bb6d4544c8cc558c30d79f9c85a87e1a95611400b7c7dac5673d800'),
  debug: {
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('81925c2e525d9fbb0ba95b438b5a13fff5874c7c0515c193628d7d143ddc3bb487771ad73658895997a88dd5b254ed29abc019bfca62c09b8dafb37e5f09b1d380e084ec3623d071ec38d6b8602af93aa0ddbada307c9309cca86be16db53dc7ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db3675ff70ce9006d166fd813a81b448a632216521c864594f3f92965974914992f8d1845230915b11680cf44b25886c5670904ac2d88255c8c31aea7b072e9c4eb7e4c3fdd38836ae9d2e9fa271c8d9fd42f669a9938aeeba9d8ae613bf11f489ce947616f5cbaee95511dfaa5c73d85e4ddd2f29340f821dc2fb40db3eae5f5bc08467eb195e38d7d436b63e556ea653168282a23b53d5792a107f85b1203f82aab46f6940650760e5b320261ffc0ca5f15917b51e7d2ad4bcbec94de792e229db663abff23af392a5e73ce115c27e8492ec24a0815091c69874dbd9dae2d2eed000810c748a798a78a804a39034c6e745cee455812cc982eea7105948b2cb55b82278a77237fcbec4748e2d2255af0994dd09dba8ac60515a39b24632a2c1c840c4a70506add5b2eb0be9ff66e3ea8deae666f198edfbb1391c6834e6df4f1026d'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac48135672556358e78b5398f1a547a2a98dfe16230f244ba742dea737e4f810b4d94e03ac068ef840aaadf12b2ed51d3fb774c2a0a620019fd1f39c52c6f89a0e6067e3039413a91129791b2af215a82ad2356b6bc305c1d7a828fe519619dd026eaaf07ea81cee52b21aab3e8320519bf37c2bb228a8b580f899d84327bdc5e84a66000e8bac17d2fa039bb2246c8eacc623ccd9eb26e184a96a9e3a6702e1dbafe194772394b05251f72bcd2d20f542b15b2406f899791f6f285c7b469e7c7b9624147f305c38c903273a949f6e85b9774aeeccfafa432e2cdd7c8f97d1687741ed30d725444428dd87d9884711d9a46baaf0c04b03a2a228b7033be0841880134b03b15f698756eca5f37503a0411a9586d3027a8b8b9118e95a9949b2719e85e4a669d9e4b7bb6d4544c8cc558c30d79f9c85a87e1a95611400b7c7dac5673d800'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'Modified Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [h2b('')],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0], MESSAGES[1]],
    disclosed_indexes: [0, 1]
  },
  output: false
}, {
  name: 'Missing Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice(0, 9),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8]
  },
  output: false
}, {
  name: 'Reordered Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice().reverse(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: false
}, {
  name: 'Wrong Public Key Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: h2b('b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6'),
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('ffeeddccbbaa00998877665544332211'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Presentation Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */
