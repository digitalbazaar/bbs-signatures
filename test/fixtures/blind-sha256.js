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
  commit_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_')
  },
  sign_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_'),
    count: 1
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
}, {
  name: 'Multiple Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: COMMITTED_MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'BLIND_H2G_HM2S_'),
    mocked_random_scalars_options: {
      seed: BLS12381_SHA256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 7
    }
  },
  output: [
    // commitment_with_proof
    h2b('8707ce71651e7fadbdd39cd88e83255629aacd969186eaefe95ea27935ab54af325220bb410af7f4389f85adc630548a02ff284a86147a4fc93da14be0c8f2c8df53b0057f71adee985b3b72bc759c2642187bd6cdc9f9e78f4d44b7fea7cb41563058647bc49614cdbb30b8f88264112e4b9aed8849609ab34eed40a83fa095d7ed156e9f89e7bb64bec73cd02ccd8814aa43b6f46cf2b5684125fbc25c0285aa525dc3aba6f21a597f7b5a424a014c5162983082c2d63ff500fc06b5200423fb647bf67815bb9baf76d5a8ccb665ba120fff68b6fd180f4b4c43fb437d68cff8eeac230a47d331b4a72f124957042e4664bae34f486b5c33d1120eaa676e6e302ed1f79739b75e074baa702beb7939'),
    // secret_prover_blind
    h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589')
  ]
}, {
  name: 'No Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('8bd94b05cd4e006145bc974cf5cdcc80e544a8c4624b0a7f6a5509430c79be788be86536b725ea93dd0a035b4ef822631dc4e8c1a02cc212cc9f914ecfab3470901d5d1573e4d03653af76ebf3bd891a226635ac82ee6cc94bc20135471365d2bb278e21eae8e71661ecd3f6301c7ba3'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    secret_prover_blind: h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 2
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHA256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('a001fb708fb48dc1c02c84114edfe4cce81a80c067159050c29b903680621c830e93213872305957c25122de78194a913165b2ffdd806e3152c4e2d712c396bd2619028cce1857d07ca96a9f5157f4c8'),
  debug: {
    B: h2b('aa963d9eae5bf642b7b080c9b6cf33f19564e501638d85a0a1f862a86ee0b26e992fe52bbfc103c82038a41146994ede'),
    domain: h2b('1666eb9faaa4d028797e16a9e89478b067615039c763c931c3df5012ef153b33')
  }
}, {
  name: 'Multiple Prover Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('8707ce71651e7fadbdd39cd88e83255629aacd969186eaefe95ea27935ab54af325220bb410af7f4389f85adc630548a02ff284a86147a4fc93da14be0c8f2c8df53b0057f71adee985b3b72bc759c2642187bd6cdc9f9e78f4d44b7fea7cb41563058647bc49614cdbb30b8f88264112e4b9aed8849609ab34eed40a83fa095d7ed156e9f89e7bb64bec73cd02ccd8814aa43b6f46cf2b5684125fbc25c0285aa525dc3aba6f21a597f7b5a424a014c5162983082c2d63ff500fc06b5200423fb647bf67815bb9baf76d5a8ccb665ba120fff68b6fd180f4b4c43fb437d68cff8eeac230a47d331b4a72f124957042e4664bae34f486b5c33d1120eaa676e6e302ed1f79739b75e074baa702beb7939'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHA256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('a9e3a078815b3f7c9d2a9310a5a5b6da193214cb6be6ef77dbbc8fac958ce26bec96ded9334aa0d56dc37992906b6a7d6ead4a7dafea18d3514ea4206f9a93b225debe99b8628ccad921d9253e39561c'),
  debug: {
    B: h2b('85f7a6c2593bb4c1ecf6bd84aa3fe29e4d2c7d59f236523efbad684a25b941ccf9abb83a8531e9badb7bf1bdb433808b'),
    domain: h2b('1a0842369c4a79ed4709bce26963466699fafea687246b1074c91d9002c4bd1a')
  }
}, {
  name: 'No Prover Committed Messages, Multiple Signer Messages',
  operation: 'CommitAndBlindSign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('8bd94b05cd4e006145bc974cf5cdcc80e544a8c4624b0a7f6a5509430c79be788be86536b725ea93dd0a035b4ef822631dc4e8c1a02cc212cc9f914ecfab3470901d5d1573e4d03653af76ebf3bd891a226635ac82ee6cc94bc20135471365d2bb278e21eae8e71661ecd3f6301c7ba3'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    secret_prover_blind: h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 2
    },
    sign_mocked_random_scalars_options:
      BLS12381_SHA256.sign_mocked_random_scalars_options
  },
  // signature
  output: h2b('b3e48d4f916c372e330b3727d14f1543cd5de4285e6c3b90692bc842e0cc1f4eed563726df615fbd77427975222d196664d8733cf38ac4c57efe85a055290cde0cd08680309218db9e04f3299985e814'),
  debug: {
    B: h2b('b16f00f40d3a60700f7da8589b876ad722279de6e6c66dd2681a6855a3d71f2976802972a4e7bcfa88e1f2e44387d9eb'),
    domain: h2b('69ab8c6eb9481bee9c3cf60dfb9d3f539023e8c6e78c6568d0913ea046752a2b')
  }
}];
/* eslint-enable max-len */
