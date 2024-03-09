/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {CIPHERSUITES} from '../lib/bbs/ciphersuites.js';
import {os2ip} from '../lib/bbs/util.js';

const TEXT_ENCODER = new TextEncoder();

export const MESSAGES = [
  h2b('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02'),
  h2b('c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80'),
  h2b('7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73'),
  h2b('77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c'),
  h2b('496694774c5604ab1b2544eababcf0f53278ff50'),
  h2b('515ae153e22aae04ad16f759e07237b4'),
  h2b('d183ddc6e2665aa4e2f088af'),
  h2b('ac55fb33a75909ed'),
  h2b('96012096'),
  h2b('')
];

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
}];
/* eslint-enable max-len */

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
  name: 'No Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: [],
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'BLIND_H2G_HM2S_'),
    mocked_random_scalars_options: {
      seed: BLS12381_SHA256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 2
    }
  },
  output: [
    // commitment_with_proof
    h2b('8bd94b05cd4e006145bc974cf5cdcc80e544a8c4624b0a7f6a5509430c79be788be86536b725ea93dd0a035b4ef822631dc4e8c1a02cc212cc9f914ecfab3470901d5d1573e4d03653af76ebf3bd891a226635ac82ee6cc94bc20135471365d2bb278e21eae8e71661ecd3f6301c7ba3'),
    // secret_prover_blind
    h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7')
  ]
}];
/* eslint-enable max-len */

export const CIPHERSUITES_TEST_VECTORS = [
  BLS12381_SHAKE256,
  BLS12381_SHA256
];

// hex => bytes
function h2b(hex) {
  if(hex.length === 0) {
    return new Uint8Array();
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map(h => parseInt(h, 16)));
}

// hex => scalar (bigint)
function h2s(hex) {
  return os2ip(h2b(hex));
}
