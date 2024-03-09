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
  output: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
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
  output: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
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
  output: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
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
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [MESSAGES[0]]
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b(''),
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'Modified Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
  debug: {
    random_scalars: {
      r1: h2s('60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337'),
      r2: h2s('2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811'),
      e_tilde: h2s('6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd'),
      r1_tilde: h2s('0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8'),
      r3_tilde: h2s('639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1'),
      m_tilde_scalars: []
    },
    T1: h2b('8ce960f5155d05a1795cc3422e6c975f6436a9b70c17ffbfd776346c93a9682bb6c74abd70d8c32781ae783ec45ea005'),
    T2: h2b('ab9543a6b04303e997621d3d5cbd85924e7e69da498a2a9e9d3a8b01f39259c9c5920bd530de1d3b0afb99eb0c549d5a'),
    domain: h2b('25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c'),
    // proof details
    Abar: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa'),
    Bbar: h2b('8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2'),
    D: h2b('aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a'),
    eHat: h2s('0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd656'),
    r1Hat: h2s('67373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b3'),
    r3Hat: h2s('3833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070'),
    challenge: h2s('067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('815064df090feebe9d089343add9ce0c46c55c45a7a75913c3ffe980cd51dd5af5a6b45a10dcf7c56927b3a30c99adea'),
    T2: h2b('b9f8cf9271d10a04ae7116ad021f4b69c435d20a5af10ddd8f5b1ec6b9b8b91605aca76a140241784b7f161e21dfc3e7'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481352bb6fce6084eb1867c71caeac2afc4f57f4d26504656b798b3e4009eb227c7fa41b6ae00daae0436d853e86b32b366b0a9929e1570369e9c61b7b177eb70b7ff27326c467c362120dfeacc0692d25ccdd62d733ff6e8614abd16b6b63a7b78d11632cf41bc44856aee370fee6690a637b3b1d8d8525aff01cd3555c39d04f8ee1606964c2da8b988897e3d27cb444b8394acc80876d3916c485c9f36098fed6639f12a6a6e67150a641d7485656408e9ae22b9cb7ec77e477f71c1fe78cab3ee5dd62c34dd595edb15cbce061b29192419dfadcdee179f134dd8feb9323c426c51454168ffacb65021995848e368a5c002314b508299f67d85ad0eaaaac845cb029927191152edee034194cca3ae0d45cbd2f5e5afd1f9b8a3dd903adfa17ae43a191bf3119df57214f19e662c7e01e8cc2eb6b038bc7d707f2f3e13545909e0'),
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
    T1: h2b('896e010e182f0718400b1e694ebc740215c2dd703f5988b7312be5a7f824f86b221dd89d7a66f61b9fb238a73169e3bb'),
    T2: h2b('8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('958783d7d535fe1860a71ad5a7cf42df6527246300e3f3d94d67639c7e8a7dbcf3f082f63e3b1bcc1cdad71e1f6d5f0d821c4c6bb4b2dcdfe945491d4f4a23d10752431d364fcbdd199c753f0beee7ffe02abbad57384244294ef7c2031d9c50ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db36771c74f1feec7f67b30e3805d71c8f893837b455d734d360c80e119b00dc63e2756b81a320d659a9a0f1ee57c41773f304c37c278d169faec5f6720bb9187e9333b793a57ba69f27e4b0c2ea35271276fc0011306d6c909cf4d4a7a50dbc9f6ef35d43e2043046dc3041ac0a9b893dfd2dcd147910d719e818b4189a76f791a3600acd76623573c1796262a3914921ec504d0f727c63e16b432f6256db62b9667016e516e97e2ef0bfa3bd192306564df28e019af18c50ca86a0e1d8d6b08b0641e549accd5e34ada8903d55021780865edfa70f63b85f0ddaf50787f8ced8eee658f2dd61673d2cbeca2aa2a5b649c22501b72cc7ee2d10bc9fe3aa3a7e169dc070d90b37735488cd0c27517ffd634b99c1dc016a4086d24feff6f19f3c92fa11cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652'),
  debug: {
    domain: h2b('41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7'),
    challenge: h2s('1cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356d60aa96c9b53ff5c63b3930bbcb3940f2132b7dcd800be4afbffd3325ecedaf033d354de52e12e924b32dd13c2f7cebef3614a4a519ff94d1bcceb7e22562ab4a5729a74cc3746558e25469651d7da37f714951c2ca03fc364a2272d13b2dee53412f97f42dfd6b57ae92fc7cb4859f418d6a912f5c446002cbf96ee6b8f4a849577a43ef303592c33e03608a9ca93066084bdfb3d3974ba322b7523d48fc9b35227e776c994b0e2da1587b496660836a7307a2125eae5912be3ea839bb4db16a21cc394c9a63fce91040d8321b30313677f7cbc4a9119fd0849aacef25fe9336db2dcbd85a2e3fd2ca2efff623c13e6c48b832c9e07dbe4337320dd0264a573f25bb46876e8153db47de2f0176db68cca1f55406a78c89c1a65716c00e9230098c6a9690a190b20720a7662ccd13b392fe08d045b99d5010f625cd74f7e90a'),
  debug: {
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
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
    proof: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481352bb6fce6084eb1867c71caeac2afc4f57f4d26504656b798b3e4009eb227c7fa41b6ae00daae0436d853e86b32b366b0a9929e1570369e9c61b7b177eb70b7ff27326c467c362120dfeacc0692d25ccdd62d733ff6e8614abd16b6b63a7b78d11632cf41bc44856aee370fee6690a637b3b1d8d8525aff01cd3555c39d04f8ee1606964c2da8b988897e3d27cb444b8394acc80876d3916c485c9f36098fed6639f12a6a6e67150a641d7485656408e9ae22b9cb7ec77e477f71c1fe78cab3ee5dd62c34dd595edb15cbce061b29192419dfadcdee179f134dd8feb9323c426c51454168ffacb65021995848e368a5c002314b508299f67d85ad0eaaaac845cb029927191152edee034194cca3ae0d45cbd2f5e5afd1f9b8a3dd903adfa17ae43a191bf3119df57214f19e662c7e01e8cc2eb6b038bc7d707f2f3e13545909e0'),
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
    proof: h2b('958783d7d535fe1860a71ad5a7cf42df6527246300e3f3d94d67639c7e8a7dbcf3f082f63e3b1bcc1cdad71e1f6d5f0d821c4c6bb4b2dcdfe945491d4f4a23d10752431d364fcbdd199c753f0beee7ffe02abbad57384244294ef7c2031d9c50ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db36771c74f1feec7f67b30e3805d71c8f893837b455d734d360c80e119b00dc63e2756b81a320d659a9a0f1ee57c41773f304c37c278d169faec5f6720bb9187e9333b793a57ba69f27e4b0c2ea35271276fc0011306d6c909cf4d4a7a50dbc9f6ef35d43e2043046dc3041ac0a9b893dfd2dcd147910d719e818b4189a76f791a3600acd76623573c1796262a3914921ec504d0f727c63e16b432f6256db62b9667016e516e97e2ef0bfa3bd192306564df28e019af18c50ca86a0e1d8d6b08b0641e549accd5e34ada8903d55021780865edfa70f63b85f0ddaf50787f8ced8eee658f2dd61673d2cbeca2aa2a5b649c22501b72cc7ee2d10bc9fe3aa3a7e169dc070d90b37735488cd0c27517ffd634b99c1dc016a4086d24feff6f19f3c92fa11cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652'),
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
    proof: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356d60aa96c9b53ff5c63b3930bbcb3940f2132b7dcd800be4afbffd3325ecedaf033d354de52e12e924b32dd13c2f7cebef3614a4a519ff94d1bcceb7e22562ab4a5729a74cc3746558e25469651d7da37f714951c2ca03fc364a2272d13b2dee53412f97f42dfd6b57ae92fc7cb4859f418d6a912f5c446002cbf96ee6b8f4a849577a43ef303592c33e03608a9ca93066084bdfb3d3974ba322b7523d48fc9b35227e776c994b0e2da1587b496660836a7307a2125eae5912be3ea839bb4db16a21cc394c9a63fce91040d8321b30313677f7cbc4a9119fd0849aacef25fe9336db2dcbd85a2e3fd2ca2efff623c13e6c48b832c9e07dbe4337320dd0264a573f25bb46876e8153db47de2f0176db68cca1f55406a78c89c1a65716c00e9230098c6a9690a190b20720a7662ccd13b392fe08d045b99d5010f625cd74f7e90a'),
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
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
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
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
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
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
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
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
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
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
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
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
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
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
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
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */
