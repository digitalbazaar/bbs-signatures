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
  signature_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_'),
    count: 1
  },
  proof_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_')
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
  operation: 'CommitAndBlindSignAndBlindVerify',
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
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('a001fb708fb48dc1c02c84114edfe4cce81a80c067159050c29b903680621c830e93213872305957c25122de78194a913165b2ffdd806e3152c4e2d712c396bd2619028cce1857d07ca96a9f5157f4c8'),
    verified: true
  },
  debug: {
    B: h2b('aa963d9eae5bf642b7b080c9b6cf33f19564e501638d85a0a1f862a86ee0b26e992fe52bbfc103c82038a41146994ede'),
    domain: h2b('1666eb9faaa4d028797e16a9e89478b067615039c763c931c3df5012ef153b33')
  }
}, {
  name: 'Multiple Prover Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
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
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('a9e3a078815b3f7c9d2a9310a5a5b6da193214cb6be6ef77dbbc8fac958ce26bec96ded9334aa0d56dc37992906b6a7d6ead4a7dafea18d3514ea4206f9a93b225debe99b8628ccad921d9253e39561c'),
    verified: true
  },
  debug: {
    B: h2b('85f7a6c2593bb4c1ecf6bd84aa3fe29e4d2c7d59f236523efbad684a25b941ccf9abb83a8531e9badb7bf1bdb433808b'),
    domain: h2b('1a0842369c4a79ed4709bce26963466699fafea687246b1074c91d9002c4bd1a')
  }
}, {
  name: 'No Prover Committed Messages, Multiple Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
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
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('b3e48d4f916c372e330b3727d14f1543cd5de4285e6c3b90692bc842e0cc1f4eed563726df615fbd77427975222d196664d8733cf38ac4c57efe85a055290cde0cd08680309218db9e04f3299985e814'),
    verified: true
  },
  debug: {
    B: h2b('b16f00f40d3a60700f7da8589b876ad722279de6e6c66dd2681a6855a3d71f2976802972a4e7bcfa88e1f2e44387d9eb'),
    domain: h2b('69ab8c6eb9481bee9c3cf60dfb9d3f539023e8c6e78c6568d0913ea046752a2b')
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('8707ce71651e7fadbdd39cd88e83255629aacd969186eaefe95ea27935ab54af325220bb410af7f4389f85adc630548a02ff284a86147a4fc93da14be0c8f2c8df53b0057f71adee985b3b72bc759c2642187bd6cdc9f9e78f4d44b7fea7cb41563058647bc49614cdbb30b8f88264112e4b9aed8849609ab34eed40a83fa095d7ed156e9f89e7bb64bec73cd02ccd8814aa43b6f46cf2b5684125fbc25c0285aa525dc3aba6f21a597f7b5a424a014c5162983082c2d63ff500fc06b5200423fb647bf67815bb9baf76d5a8ccb665ba120fff68b6fd180f4b4c43fb437d68cff8eeac230a47d331b4a72f124957042e4664bae34f486b5c33d1120eaa676e6e302ed1f79739b75e074baa702beb7939'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    verified: true
  },
  debug: {
    B: h2b('ab6c841535ba75d568e913d716cf2920624044c5cd99cfbebb564d5c0654a9bbc3c458cc3c51349ece6ec40223f7e2a5'),
    domain: h2b('386bb1c7c4d1e3b95686cd66ad21ba8302f9f87290cc800a79c910f0e96dbd02')
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages, No Signer Blind',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('8707ce71651e7fadbdd39cd88e83255629aacd969186eaefe95ea27935ab54af325220bb410af7f4389f85adc630548a02ff284a86147a4fc93da14be0c8f2c8df53b0057f71adee985b3b72bc759c2642187bd6cdc9f9e78f4d44b7fea7cb41563058647bc49614cdbb30b8f88264112e4b9aed8849609ab34eed40a83fa095d7ed156e9f89e7bb64bec73cd02ccd8814aa43b6f46cf2b5684125fbc25c0285aa525dc3aba6f21a597f7b5a424a014c5162983082c2d63ff500fc06b5200423fb647bf67815bb9baf76d5a8ccb665ba120fff68b6fd180f4b4c43fb437d68cff8eeac230a47d331b4a72f124957042e4664bae34f486b5c33d1120eaa676e6e302ed1f79739b75e074baa702beb7939'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s(''),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('91902b68ac869d0b250355be499fe555e292759de6cad9c28eec51d3f4bb5f435238636538d347be44a4b33e0edbfd4d1bc5b0082b29eea3b3aed2b718706a8d08ada2fe623279472fa5e4c571c44ebf'),
    verified: true
  },
  debug: {
    B: h2b('8444fca0a990ab19c0c7c7cd93ed31406e5dde17c16f1333c2e42284ddfb88e062fed9fd2aa6ae6cc81e6b9a6251fcb6'),
    domain: h2b('386bb1c7c4d1e3b95686cd66ad21ba8302f9f87290cc800a79c910f0e96dbd02')
  }
}, {
  name: 'No Commitment Signature',
  operation: 'BlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b(''),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    signer_blind: h2s(''),
    signature_mocked_random_scalars_options:
      BLS12381_SHA256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('8c21175e0465339fd9b32aece83c43402b8b467baf3085028ecb5669e76e093c0db878bfd4e6121b2b86260fd38f11ca37fc2f16f145ba600b240eb96a40960f7aac7416f2390225e7166863db321b16'),
    verified: true
  },
  debug: {
    B: h2b('853ff87eda30796f5997ec3fb9fffcefa78b0b457ce9f2487b8afaa0ffa5098053dc91a65e0b169d97f7b1123e80ab14'),
    domain: h2b('160cf879138e86f8f6025c41ec94434432a315c33dc6b90c38f1b21ce101418c')
  }
}, {
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 6
    }
  },
  output: {
    proof: h2b('8b29fc429ae913cccb71f730fa61fd220a8ce673c6eb704106783b7e00a5fd5eb43fd06e9e76b068ab5ca6da93c0201b883bd8caf5ab4af7b3487f50c68c40a310ff3187be9eef536456ac11ca69c6bc43a96307633ee796ddb32346bb47018391f41e1c03cda63ebd5b112950aaa38b808986492873ad40cecf3b8ca9846837da824bfafd62bb8aea56938b653c7bb76b48c87dd7c7a1627d17281a4ba5a403df760ba8dc8599d383960f63a107618e5c77e27c61832dde296888c21e1acb9c6712f37dc916b91dcec2ead637eb7c926c506ddbddf2753c47b1718bc5fa49a3c1f094502b6b119e71fa0632cf64819f6ea38de039179cf6b168deb28f8792266b22d4e2403e7c8dccb23bc95a160e0f1d100fffd917533ac135507a55889223ec03952e420637681ff74d30b2e2246a'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  }
}, {
  name: 'Half Prover Committed Messages and All Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 8
    }
  },
  output: {
    proof: h2b('91b42b089d23d096669b0cc5cfb238490eb0bd668d32d8092ac38ca526cc8daf7800ca804eb81c0ff48cf95c83669442b811a11fcd97e51603f677f11970ae060afe7e54edc8f436f9851b3a55d93694333122318f31405bc7a74bf15397994b89d091cf605c67c78231611d5fb4af9b9f34177d13fc5d6b197387d5b4098fb5da0b10f26a7235816f71d494e95ba0bf47cfc48802eb69a0ea54f165add455eca6058887e3a9b427bebb4e1c38cfd3b04e6d5d2989f81fc471b2babceab70646723f1d3fca309676d944d616d93b0dfc16453fcbf1a60200091cdf4b1ab6ce05b2d7d53c1b87f1940dd76fdd478e29ba1d6fea92b03fddab48f3a159961ec0f1e3ba48e3e91298457787514854ca7ae71554185a64ac4c9f5f95f7f160dab89a906174053dc01b6a4f4060dd289495376dff8d460e138e62343ec7af941b453025ce4ef1b5fb6855ae8f86d8027df71069f0ace60d26249dbeccd3db7bff56272695cf1d4481b95780b5bd865b0a229c'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  }
}, {
  name: 'All Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: {
    proof: h2b('97154dab37939b7b94dc0b3e699c248fc2511e9e246c8ba1ef82777a293588c4a80d24539c547b059b9e2a8e5b94dac78ed7c60601ce7843cc18a7119927cc109dc152152d3131d10bd04b140127ec7d5c6a631665e58850b847ea221ac9e1a3b549e5bc46d81c842c65b32c533e0222aafbbee4e7009cea9f03c5840332295c4e58620cfe666706363c190e1398d4190c6556cfc9ddf20c0f62ecd18c2d24678655f33312a2677f01a75894fc8977c01fa19d20f9771f4a3ca6f6e6c0ba00b085bc9264c1f343e0509f1f44bf8a2ff624c45dd583626002101db0b053f9e3a162b1abd6b1dae6683ceaa3c0e4ea696256260ea1eca9712c353fc3266d156a8f53b1911ee2fb54d0ac9e47cb4d6d20e93d42e3c80d6954565ba2e84a48141858ce9c2f9499b4065c5206ac8ea70ed1bc21b5e9cf868a8bf94f4f617d316562b2ebefbcfd3825975013c834babea0fbc662407c6d35185e29d86f9518bb1cd530c97a9f0c49ad26b20add7ddd8eb2166b3bff20c58d47fa72d04d12bde322ca29aaeb07936a82655529d26f360a5b18015ddb3ea266abf629e3e4c7e86425c90f481078b1b111410078fff5909b30b5cf641301a24e923b5958950fd24c2d32cce7860a5c7e6c733c503da28eebff28c7'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 2, 3, 4, 5, 6, 8, 10, 12, 14]
  }
}, {
  name: 'Half Prover Committed Messages and Half Signer Messages',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 13
    }
  },
  output: {
    proof: h2b('86511a727d3930032106cbabd68480c8893cac0698ce156ff7060eb3a9a0d0578e9c80b3a248948ece27c871b281ca9da29e15b5e254a4ce4df998a3b83ec8daee50a35867fc4a545b550718b24385c086c8ce95fb569b9d5b08afc1a63d6a3eb89b61dbac567a7ccfd9fb1462e806170dd885b719b64690025989b696cc50ca7aa625f373f7f3ddb99a01cdc3f1e2442663dc0600cb09ab26066b933f3a6a82f214309be31cc02362bb548e5eef4a04669197a372cb6937a00450c115675d3e026a33af2ec80705a7517995a22661d21c9e4c0b464e798eca920330104a4c760074342f38b0372a70473904086465606803d9dc77606cf00c3832b534de13653f33a4723045bee32990a553c5e1d0ce70190e8e458a33ec62fe9b3424e46bf77fe26a2969b74f5a242c4697a286f15057226bd9ab05335e6b24584bd477179e7623e3b6047c26c1b8e57dace080e114110d126537d9dc2eeb4ec611083a79bce67c29696700f66f86ad4bcb6875d2f664098709700baf0beead805f9f374a178edea6172a315f4d38aa02271afdd0f55f580b870d6a813b4e5b7bc0530dace5dc600bdfd1134986e5aaff4108a608865a196f610cbc40385773bdb5dead610078adcd4bc4fe2c83f28c355429982d2570269168d71f46d499e124dbadf5f61456cb969b2814b00f61bc87e5cb166e7c40163f0c0124d1bffc9941c3e805d37b1a7cffd15f39ca98e145a9c62158ac11'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5, 6, 8, 10, 12, 14]
  }
}, {
  name: 'No Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 16
    }
  },
  output: {
    proof: h2b('a3e58b26112de65d6e6bbeaa662ccad8a2222fabc49fb792fef994681e5424e795e8556d565efd94048507701b7182f782f8697e748f3fa9a75bb87b44bebaa16c730d97453f91db189851ad5695c02741b245ce212cf5b86fe83c6cf6f6d0d1937c9ec0e1f8fea1bd6b259ad52c28bdf3b6f8990804037d096030786dd4609c1c729e0b29286ec2cd53470bc202128814b9ac512da494b0bead3c7d345e3f8aa557db59404bf2e7d9409c9c9a412c4b5fc92c9ba3dd9b2198905879f13ba2090bfac0a78faf7ce19174bfb16266c9383f5e12dd1456b533d7878c7bb2813174df9bbe7b3ece410e4a8890d9fe7775f410e48d35b0e0e656c6ada9176ec8a41bdac4b4d6031410078b2a5a8e8f90cdc430e551c1a94b5353d071cf945ae03d204f347905e167340bfe6f42a566b7cc793cd692ba74a2442aa95c967976d734714e17a98c50f067da5c0c2cfef91100ef6c97e9ebabfad141878c73af82d6a3b36d25baf0e72b7391baef0f220d73c6442c09915de3ed89717d19e5375684f03efb1c8eb65db1049446b420c2c682855703f84f5781cd0bcf944d6c13e883ea03365311256b918e1279067b42cccd99f902a69db49e53c1df89b13cd9ab98c90dfbb1f6ac7a3645505fa04d593dca5f1703ef8b71b78aa134ce1a8e819ba6dd5caac56909870d7eb948b903c7e0d977444df59a158af54eaa3779c575436186fa6804cbe16397ef3759e35f254eda037e237c6a506319becda29e32cad64a3a941209e92ea9d7e55dd5cf6c7d25747990675eb271b8aa0d3a38111a9ee488f849188e2b7cce5355d79ae2b4e8b1d055583b62cd581bb9b6a4c31b194408959d06d1995f2094f27943d29e819a52bb91ed'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [6, 8, 10, 12, 14]
  }
}, {
  name: 'Half Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 18
    }
  },
  output: {
    proof: h2b('b3c858ca8b1193a759acfcbc985345103384565e42b5523443031879f2bc757a1714c442882801146e7e1222b8c72fa59195d7791d8f1c1f5b8e0aca00929f64abbce082b0667c1e98aff024a66351da986aa15a598170510397d783eb90192fb3c7144b00468715699f049b547b8e49d66e2ddd29a19ebc84cc7e1c75f5449310e4a711decd25a4d85cbe3bbc18fa613fe26826949a6f966ad2a1f6665a8921af9f48bd73adc8cd7902d6c85822f2553ee684f9aec8d4f41d2d3cae7ef0ddfb0887132a8a178bcfa2ea5da363a37507194f79c59607954dd766af7523ffa56e247ba9c7dbfdc99b01a42513404fa16f38940feb9a940bb54f08206bbb246e809bf0a942d6d52ddd5395bf5c2ee4a134295858716ba66da7af44b63c3d9bca66f01c427490146638cdbd5013f5be295c276045daefca9da13c3ef5459523fac4bbb7e6eee29e894d4a6142617a7dac1c690e2ca6a24c10a0da44251c2229b469905f81312f3edbe00421e3b69ed1763a05e6102a2c85fdd20680070f360e8cfa50e8db780b80a721f86594e3b0df74ac31b6aec65f245592a581a78a0cbeb8fffa5ca3dd2f0f136f27267d5e4db625ba5a1b1b4a4dde9fb74f80e1a1a7140a21f6850092bcd525586f41eb110309754d3b6a2c11577e3327dc9553de5ec80203d34c9541fb603e442af297cfebef0a6c12500ae60103717bdc2dbced805552d7569bae9d6d45a984c08437b6d9135ab55c97b31abe6f3815021308a4b2393f45b0446a6e2317aa0f1b3de4ffc7703d5f5178d55210bdc14faa57a8900b31684719db9d68724a5b7453e88329ac36e01906799a42e2f4e2720996ace5a946051ac5c8a053b68178e38dcb285fc7dacf5207714880e95c0c0136da4a1a33f229830f805cee393b3e58d88a4abd6e5b8c6c5cf8d534c85b01892816cc55b0511a581756c6b575773be5381be1a3f17fb493'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5]
  }
}, {
  name: 'No Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ad7169408a137b7365c6f156d5011b72e57e027a7326dc4fb95128099af692fe7b1f7208b98ccbf717dcde22a611d2543ebd9679292532d6cd955975365fe5a260336f1329509e3e1fbce1bd2d9b5ef6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    signer_blind: h2s('10e75ca49d242390896d9dd943b97ff23b8cb780bf27df185f51b33abaaa94e2'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 21
    }
  },
  output: {
    proof: h2b('83ca9b4dc4a514497c22f78274a1d53414e5e5bc325f6c606386e033140416dc306e6f97d4167f57afceb5ad9eb69f51a9573227b8f384a7835808d9285a1c3a2baabef4c96f73be3077d8d11b045287e30642de975eda73b60f8ec4f56a1211b0e88764a49abae79d2e09286c7656fa49c7ec2881da9baf1bda300bf512d7e112d7ec04d478c5781ae7aa1d47f6abdb58d4f5c93d408491e274c9db8226e677a75f0d3c48c3ce143293b2f3ec21c56b715c3d199a6a334ab3a01a54caa670079ec782004d61f10dd73f6d364122b9a33340bf2d3f20fb1488b240184b62cfd6b016ca48fc4c0defdbd696ed26b010cc21f70c9b7d5a80889c5be0a23338f3f2facbe7867bdafd257dedd76eef3854095c687f57944aa01b035330ea8686965d12df901100b7f11c0ef689983171efd12e05a135fea22212ecb1fcd12f6b5cffbea5480f989cf24453d4eab9f088d6225597be7331449718cddf19ef02f641ffb10263f93e79031bcabae5780c886fef2fcfe2d6c0313f909719c0aaebf8d81004af6fff71bff0af2caa0f020ac9520a13e2b58a2d8064e3ad2697ddc4d0444b55169bdf877ba313467d7992358060413e69ac102f38eb66bdd8d21e7e9af7b3472ae62e7c3c27688870b16582363eaf168da96258c25d3037117843e5a8df52da151b462dd3d7fb09a31200cbf061cd6d9a87fa576e315361e56359ce04b704ee14f21c6634ef5ded4a07fa815bc15051bc8588b4b18b618f01474c2b8698571b43aa03d8b3bedb44ca6d3982c40ecc2be6e4607a5f219dcf1be6befaa626c0135ab9e0d6aabaf0b0c912c8fec8b56615d3daec48a5faad59c1c00daf1665a21abc86a9e15f12a5c156f196d822ba261c9ffdcdcc8d9fa1db7ab025f2edb3a08e8c79aa15e0bdf8a8550dc6b87a56ce287798bfc6357adf247a072ebba9dec8a8aecc2f0799b81b75178520da96f37d35027b988e5117414f0572db8e6339b3404998ec64fc04128a59e19d22a9bc9700feea1878c6f7941c67ad4adc40d738e1517e4404464799ed170726f72b4a4e0ce4208491db5c83c601b19a9a4171aa0f5b8a5eb5c06c973a7ff43db76d10a7'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: []
  }
}, {
  // spec test vector seems wrong; test will pass if checks to ensure that the
  // right number of random_scalars are produced are ignored
  skip: true,
  name: 'No Commitment and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('8c21175e0465339fd9b32aece83c43402b8b467baf3085028ecb5669e76e093c0db878bfd4e6121b2b86260fd38f11ca37fc2f16f145ba600b240eb96a40960f7aac7416f2390225e7166863db321b16'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: [],
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s(''),
    signer_blind: h2s(''),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      // should only be 10 since there are no committed messages?
      count: 11
    }
  },
  output: {
    proof: h2b('b52167f9cee8792582213798dc6909be7ac4a9084750b68d31abcc0c1231cc870e2b4c06e4799f2913d95fd2b84434a3b1392df3fe62719647cbf081f0677df748bf49a072551cfbee0a8d8772fb7b32208213ae3ba24c2ac8d2cc55aba99b7cb5d7b5546131fa21e6fe6b6715b81532d18ecc63908ac25dc2fd3b4dd054600ac6b2f82d05bef0e898d9b90f89df2aea62b346bbdeffe56401e3869fecf66086f1a94b7d12d96737fbcc131aaafe0fdd602536c489001cc775398558e678e9f67c36233ced8c104d99f66a70cb4fd1f3524242535cef2ac8b4c357822aca9c95284a7d825ece0a961b813b917312c0271b4d3ffa3244f0be87c8ec8ddfa575c1dc23d25347f51d20b24b950a956ead3e3ee755d9171ff136d3e464cacb53464acef7085aeee0c7556d576e4e81734d460a0905a0ef594d82f08d3d1d791e3278ddb784653f3a5c3fb789470fdc3f768c56007aab7709a1b82fd3c14c60778c15f662d30920dab48034fd703e70793a8204f34235f5fb7fe38959b58e11a539beb9e1e6e16aad50d7a59d3c7ae33e30594995eebf1985ce952985b23287b454c89fc72b7a63829dc95fd2aa5bc68a146a'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6, 8]
  }
}];
/* eslint-enable max-len */
