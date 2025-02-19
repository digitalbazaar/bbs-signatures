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
    mocked_random_scalars_options: {
      seed: BLS12381_SHA256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 2
    }
  },
  output: {
    commitment_with_proof: h2b('849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf5306bcabf3e7cc95f5ba98cdd9bf3768'),
    secret_prover_blind: h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7')
  }
}, {
  name: 'Multiple Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: COMMITTED_MESSAGES.slice(),
    mocked_random_scalars_options: {
      seed: BLS12381_SHA256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 7
    }
  },
  output: {
    commitment_with_proof: h2b('a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03'),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589')
  }
}, {
  name: 'No Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf5306bcabf3e7cc95f5ba98cdd9bf3768'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    secret_prover_blind: h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 2
    }
  },
  output: {
    signature: h2b('ab54c35fb2af5c75d6368bc5772547e126d60a92205d011bb9ee5d1149432e91611fd376fe5b79d6ed7c2ba00a19b7434744945fd77bf02cd4628a6e5deeae50768116d55510251bb6a716a38340e184'),
    verified: true
  },
  debug: {
    B: h2b('9964a978251fcc52c918dee3d8f102d2152fa7a805df85b1e91e0c45d4d8d7c02aab78353a240176f6a33899b98b3379'),
    domain: h2b('0b3a152bc770ff9e21f09ac58f59c99379ca0eeb61990ba666d994014085b332')
  }
}, {
  name: 'Multiple Prover Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('b7446e6ae4e8b5707ac0108f3b1049e9ea01bd6b2b4a7dcf06e5ad1c62a9c0b1585829f0e30fba6c9761469ed908deca52ba5499cef2827b99527b4adf1f30522ce32366385ba87594b8d0e44d156eec'),
    verified: true
  },
  debug: {
    B: h2b('b21004683409ac48cab4ac654761afa96b90d72742c2a3d1c66343df47713737e6b2367f1dbf0bd917e6f8bc3fd1440a'),
    domain: h2b('13c94073eb7dbd279f60d5907c19d83e4a9ae19f99d6b3ca020785730a3f37eb')
  }
}, {
  name: 'No Prover Committed Messages, Multiple Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf5306bcabf3e7cc95f5ba98cdd9bf3768'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    secret_prover_blind: h2s('1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 2
    }
  },
  output: {
    signature: h2b('b869cccbe84dce890949db3393c963ead72d044863b2c75bc26c0adfbe08b5bb01db9e4db3313fc660ebb3283634772809d177d191bffde6fe7fbd8ca95d7b842e434ae973b7e458325b9eb23b6cf076'),
    verified: true
  },
  debug: {
    B: h2b('99c95be56780fa694d182ca279de80297eb93fae1c8f398c7bc155b0a3be3abc7c61813cfead8a35a89dc4d7118b266f'),
    domain: h2b('a2271347c620cd43982d4f53dbdd176db8c87fbec6eb15318355bdb39da7d19933f1bbb1845e7c547f8fb2e9858d1ff9')
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    verified: true
  },
  debug: {
    B: h2b('8e1c3ee4b13e5936f9cb5f87342107ed9ab4417c04d6e5d712143a54bdb476aaf4240e8a4f11a67d81feb1398f889889'),
    domain: h2b('1207ed090723fa7e41c07e970ebb647d1d043079cc2a38c650c32234f1823936')
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages, No Signer Blind',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHA256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    verified: true
  },
  debug: {
    B: h2b('8e1c3ee4b13e5936f9cb5f87342107ed9ab4417c04d6e5d712143a54bdb476aaf4240e8a4f11a67d81feb1398f889889'),
    domain: h2b('1207ed090723fa7e41c07e970ebb647d1d043079cc2a38c650c32234f1823936')
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
    secret_prover_blind: h2s('')
  },
  output: {
    signature: h2b('8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0f51f058a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a9bf75bf1f34d8858dde57119bfafd8ff56e0c54fa4'),
    verified: true
  },
  debug: {
    B: h2b('874d657ff2b90023d18c8eb1d2fbc0beb8b9c1ae98a285db1076466edd7c0a3179bc572d4f7b0e15b39cbe298d2023cd'),
    domain: h2b('1430cf0a3d8a0519a9ecf47534b6026a7671935d9854ed5e68b42fdb543d5f7a')
  }
}, {
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    commitment_with_proof: h2b('a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03'),
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 6
    }
  },
  output: h2b('a80ea73d954433eca5bff121e0ad4b41e91d2b600cc717eff3804f11ef21cc9b9b20da25387722ae6b2dd78103a3413484c3a88248f51c9bfe93cbd88dabc619ba8a432814b15f8dfe601c1cac5404986541968307c8d06acf63ab906c41177ba9e5e8f4f1ff77426d3e905b7809243e9ae10acd1013c40525c257e3fe6f1bec2a5204433d354f3508eb93e24c91e49b60e8c0bd15af07241c43301024d5d8701516307a7b1bb381fbc3bfcaefa4d092519b4996840e199e7e2c40d75d593a993ea002fe4d411a9ef650cd0416033ff04d1bb51ca8377b789a274720695c86f5e70ecb56c4abcb3b6ff88edf48677c273ca24547a67e10d4deab8b9c989c48d9414b1c05bf61b8f8ae73c9d48c37dec55c1dd59fd821e66b06a117d7248b8676e5c15da737cbeb371790a37917130e74')
}, {
  name: 'Half Prover Committed Messages and All Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 8
    }
  },
  output: h2b('a1fe94ec24e6d325d2494e10bdc395bd82e613e8dd08ca8f4eeffee294246b9321cc0e5997de7ae473a4d4c39f27b9088c815c0ff4f8ff7da0ef6d3338e048e2b28d98e148e1e8717b6ff6dfc4c74379aab5f409212986ce667c0b9ae4c48c278720d66be792af1a62989ea56f433a17f05af1f761b48b9ae2bb24418208111680d75c8b7d781186afedbe7c7f293b644cad32737358fed7adc516ec64319298fa4d22e2119db88e846f4d8665858b0930016a56245de910baa76242d3b2f48d61e78491695773063178c1f35d392198616b619fb5019a17fd6ec0bbbf6820cfe6bf8eb58801049465d86aca537126b759f76d65d2239d71584c85c371ff9bc0fd38ebd6623df2cba477ef0ffb0c0c9f35e8a6b4c2c865f4e1b0e5bc543601c0a209816a420bd9a6b71e0cf9bc330cc2078c8d74f7c741b2fc6ce3e553fe11d4ee2e02b34e81bd06074dfc892b87046a6f77fc07c8857b819c764ae92d3779b4bf76f875b4589b37daad83c6bf1889ba')
}, {
  name: 'All Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('82a7815ebceefbfb5c1728c940b8ec6efe0d64c6c53c5b7e5a01a598f3e904bf4eb43f94f3c41c2c73bf86ad6b4d9a6f87b89bb4c08ab7d0aa1afa52de982fb5f173b88db16b09a25358489da59d7d8da1f603aa83b55a6664e276e8b24985de93c5ee7b5fe52c329660f963fa3a26b9316aaddbdb83e764fdb4323be9870a9d7fa18c9136ad79d06f6de5e820631cd30a1739ba5dd8f204020cf071e8a1a5313e4a3eb1ba058c91f37f397976920eff270ff2bb79bdab9dd006752c915b22e2fff4f362a1dd663b2a178bb7ae08d1a6251e39fb11ff14b24a237ff2d8be9fe8d0db493dc019535e53dd31c0608543fb69f9fb31d1483514e65edc9c5111281409df08b88d333e4cc76fc41a45e49767523813f5e585c562933a6d7fd8b664102bd4822ba062ccee37ea50a3c9e03fc642b84c7d422155b61d69e5a832e41169bb08748ac245be18e159be1bb343afc170483a8887fe5b889adc43f410529c7fad530084b1cc90f8854d8bf402def3f90e525e4bc99b5b8b8095495651f2cb6844b91a7832744954ca5bbf9a4f9c863c6b3485ad58bdb54fa6c71058fe29296eab761ab1a2c4be2db749c40f173f8b2e03ec71a4d9d89d066763fd6a055e6a9e42a3b6a153732a42a5be5bfd2cf85b7d')
}, {
  name: 'Half Prover Committed Messages and Half Signer Messages',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 13
    }
  },
  output: h2b('906a557b649ef5fa3ae1b17f814bbf1e78936daed6ac985416ce97bdaada5e874d60f34074c5f2a8c02b1c33c3cb041294aa3da2e1bb55674a4b94d860f3477be7eb1adb763894796b285df22112a153ad13c35e4b9707046de269833e27c16d9621b73f05e4c7c543bf995e76ac1013839c6e8a9909b36e979192c5497bcc9fc534aa9296ec36ae43c398cdd328d3b606ebb0642786b508eb1d38893cfffe8c9cff3c385644bd3641e0d1cbeda08bf16902d6dfeefa3ac8f8840a5f155c54695b908e729b7f0d06fa9453d28746dfae608580fab158d2966ed54a3b528346d72d49b0d69576b1094b3b14bfcba67af81c4467b424e9ac53fbf9cf8ca7c4cd20ac61243d61d91cd937eb82cb1524e38b24bd0ef235886c9f32e139ffe0b371bf1a310dd4a81bdda3994f1c2f85bd4b775dd2b716ad1a06e4b604448a8bad5a75581b8c655652b284b1f727f52fe74ff501990b95918fdac4a00c3509bcb978370224b2c38aea21d811f30fcf623aa3f917ca0193ae9fd3ad3f82c7e1dd80c5712d280faa027b90d27ffb37fad3ea7bcc5c69885dfe74acfb07213d01cd974133e5f6c423d7e3fa118c590cbf5edac814486965aadec16206156c97e37f7ebc837f9482f2b7c97e691bf80d0d4a02ccff38794349ef189ef7e7c909dc0c420236abac3be7613c66e41dee0a3246a759225c2e5be0db5131fee3e284bb3bdc98ff34eccb03eb70cac6b8aedef376110de7')
}, {
  name: 'No Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 16
    }
  },
  output: h2b('98805466f2fb4858dd9f60cfdc24d73b5192df64fce827b6ce942a6f2c8d5b33f7eb7bf178353cf4bac91a4d6b84b536a89f504e4b46dea57ed2bc29d83993d71fb0b5a012d36aa8c3f0ba25220435be5f1b632166228bbb496eaebc1e38267eb46b5550d6e4d32d2f5559ada94828f729cac8f192a8fdb7aac7ffcf0102fef68314723ded1927965f30096e5f89103a036f32fb9980015f9d7781f86e661e90d7b01f4c4c1bca0f7e0101098d9abcb603c3945c14b8cb298eecda9e7a8271dd407e68a45c4d2d4842b7095392873ccb4f2a0136ed04e9410b8c65eced108f5b87b9c5b84c5ff95d3345f410d8a0efd51b5d24978c578859f2183cacaffc17c031c24dc58ffc29d46922e16672140d1b078b8e7e9f87d31663ee49790274b2735bc807562c8e76f3223925ad2c15093e118ed7ec82eb590d8a9227408339f4091363da652e68cdf02c0003c94e35a2085d621447c2b0840b22af2a5d62fea5e898dba51d93bdd5f23c6b448f722d95d70459fd68f59b617adeb62b0441745b0d69e865e0fc956359e137cf4706286a9764e6b7efd431cde598876b992196c15662ba6c6768ad0ed4291963ac304dfa951c41d7233d6d85d2a9ff903468590ea787d413205b56d1892fa666230c93a87756d96fe3832930f01826651f8f449a945c0a3a9b50472c2060eceb566ec39961685560f49c36b50031dc8b4339da942e5c25498919a812209bbff527c332a5e50f27a539f805caa7c1a774034906d2aae0b6c2db4696d3ed91453ea0f1e42d4129a9812dbddec71d55d3ec1598202db88e15f3ad7f8eef3098102be8f978785e2327ce643cc12df227ef05f13ab395a6d318c59e2195d410e768cdf9e7a1784c')
}, {
  name: 'Half Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 18
    }
  },
  output: h2b('aff98a4a0bc336e459d47c19816f372de628581bc626fdd20e907db10d2218dd47530fbebc78afed77f2557d344d620d9097016e84b0dc7588686bbeacb44fc55bb3004bf79e89d82ed37df3e1835975cc63a00b76685eecc4aff51426fb43cb87d8ba852fb786f1cf649271517bcc4bb72af3e3b2fa4ae57bea485b6f9886fe33d0e5bd95d21f4ccaa4d80b64692caa23d32c7368ef99f1b9ab1672ecb3ae7393a3a4d3efa6f4dc18d8563788f97d8b3fb7427593bdc21aed4332d17b94d82b8c20ea1236a756a4ec2cfa5e1050588e04582299196c1f28e04c2349c5d9e717ba6a581ed255f20bf4210f852d2cd95844fdaacf4d8339a14fe7982be4f447812616433a3e23990c180ec2540c13f9d467e996cd9a2df2bdd1b0bfe3e51c116e13888d21e26ee61d7ca070968bc13e9d3d33dce20dfc52618bfa4d340f558660f41d67d11f5af9a1e185f261a2d14eb667987d700ce77ed24e3b70c29e49c188b5963dfb16ab7c2439ec6824f738e3df128865e180a41b06b1dbad2eed8a82728fc4dd34046410345c38415d9daaa3076efbbf84b8f3c52c2bf527d10ae882b0790a7f3b6b3e2c877fbb5a7d18bda860278598f1a83c855e67e3b8f8d807b29514d2420753ace9356a39e70fe49c5f2e29cea65820b57f3b25363685a5559c577ca48046d5eaa35568a935f58dbd9dae2744eb4dfe33cbb66bc2b351f2b634f508fe2e37ae19c89f14b4d6d6f636890d62e0f4ccb9565d4f8786b429188c7351f08538aff7b760da7867683315700ab549b639a59b9025fbf67ffb34a834d8b9e893d9d5969e9022813c4529115e682758166b4d2b8af72f44b00dff7b769bb985c40bef59e18034febfd7bb5ee847b13160b0da82b28cd400c53ff004038e67b9fd49511f9e8b69df923f3aa73fb1636f1ee88214bdcd79462a1f7411e0c8ab10a8bba0140c9cddfbcdc88d7ca19dfd')
}, {
  name: 'No Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1ccaa8feb7f3a236e92b2da38462358c48a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 21
    }
  },
  output: h2b('b27d9bc8c52a582d00db93da283346751c8da54a902703110e511fa39f184ed6c464d78c81d4bbcc57b7de1b31c7644184ba8f06266dfa8b2662b756f8c89bf3b01f7f66753028dc0ca85a0417a4f6d9dae4b393aaf5c152734f210a790a5f96a2ad1aaab7c1f5167484d18bf19570e2fa4d58b481225a1a576286bac7e4353aa7cba80939eabc492347fc05f8bd701f5410ecb5faf54d4a617bddf39bcb314d750257e99db7f0b03d043f8674668479322dc83c5c1e9e05dd760a4e1b5c45a044072bfe4e0f21bea9cc6362a38664532b4e10d0e7c4751452ff3072470b6919bded88d3e591e96a4b71603944015ca36594432351d9de6309820d5a837e28e690b662a959833fd51faf6b77e7636f206385eee2d3aa1d99758e1ef310a914f1a9fa3cd8eb2feb170c13de8e36de2dd2726430e0782cd0d5eaef64d11bd871eb27b6b2a9536a4189731b32cd16ee25ba305ee01d99689e66534d58399a514b92813873ed28f377679f3aab6e977d62226dd4fa0eef43f7b69f92ca0d69588fb8339ba0b35d1fbc3623fdf2d761fa537d54b0b2cd094a8bf98f1117a8f665c5f68f101926f729185a6d830894f4864f606d47b5b5fab349b23b9be04443d1d6bef67a1755bcb5ac2d46e8af259bc449ce19edc5a4a20f5d236bf6089012df8021ebb68c756aa85528a98aa758a5524cf71ccc9867ec837576d092c68844d8ace281fd063343b212399dcd1cc80fd7cbd822e559df5616c81eb8e6e7768d8f9819b757d3a1f9211d047bdbb172c26e2e3f0a4541d7e30b05d25b6905abba445488543a16729090eb6d0a45cef159f17cea4ebdc307f9191d76dc52277cda93c0ae75d8021ced39b064229271d673cf28ec645ba56637ecf0f54982f78773cf3ae8514dfcd4932c41337c766e9d9e6041bd0a01062da4ad80106520b29888ca5c4893a8b447cf502e6672b038698bf1b7ae0d87c4e546ae98c7b6c21ad1fb56d54ee930ba9524c55705c00b05c3b6dd0c3f42ca9f9c06748cdda8c1ca428122e780a80ae78c66c1d02728ea751dce0ac100134eed0aa579badf2131c90aea352b28586cd1dc6663008e9e38866a9f383aeb')
}, {
  name: 'No Commitment and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ac477879f31a2fdb1256aaaef7880a080878ec7aa763e576d8a29ae25d1f531aa092aed33eca25c8858c5c4eba33076011f17025852ca737d12cd36df49a21cae48bd1a6ad0fdd213a2b847e9cecad1a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: [],
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s(''),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHA256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('b54ac6e1bde3f3cb16d939774db0678f6ca4076231ca919cee3284b75e9c58773d0e13952d9d12863349551a198596768b998049451200915af5a577b1d88401487920851c4ca66b15c1b23430d99edddff019282de51cf2aa475de61ae2a4ad936d649f19d0e85a19118e5e13e2beabf2d705e1db59f8945adddafc77310b0a02042093a5477d9efd4a98cb2fad4dc541dcf9f7f6d76be6702e148175465a96ce0544b6f01aa53a99c686313a12155a3ffa17787b0fea91ce58c74d7184f4ca4c0826ecc63e97b29f6f17672a14cfe139fc8043df0fe2931c4045cefa53d0b80233838fd3f6059cb6b0138b56c1d7db18cc3b3cb687bd8f88f907530b9f1a640ef0db8df8eb7b39835874560f4222995d47850de322c7ad845d6eef499848d16fd5903860de2e955792f9914df2d4da32e2598e45ae4b0d606f77599b4b12378b8fd2baf899e90258013a7fec685c550e163a988dc15ce35a3d2d4ffcc3e897baa42ff39e4dd3108ba4bb82d19b3e4120fbfaed85949f2a21b4ba61dac6403f71ae52ff26df78bf17bbcea8670363a3279717a2b1e1d34cccfddfe9c8e3729f6e92e28197a09459c6dcd56e3920a0d74418e8d35e4956443a5e4e33d3341a5aa93a817e53e6f05c84e6c432a0e3ef29')
}, {
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('95b35609efaac8ae162df13e503761f5f3ba78b056aa00954a4705133dbf4012777c99874fa769a60d5925dd4cb8e119ae8cf6d7d53a47dd9e999d09f3ffab16b175b2be6ab7cb49dc3f10e0dc22e2222a9501fb205a73205016f45437d73bd7914f246c258c1e6f3f03245ff335f65147adecd0380ecdc7ab2ffbd24609f9376b8654b3d1b918b36a06bc03dbc09ed42a1632f03627023ccd62d613a90fc0d9b51373679f33780044072ea6abc80bda4adf187ccddecc84cb95b559273bb45afae1d9f9c4fe98463ff743c39bb7855b00e3d6c7c6d7b15089ff3e3a146507bb82a3a7c16b37af0b1148f2052832611a5d11796dbb529ad9616e7e97881e5cee8d01593e4d5c61d5d584d09090b317221a7781f0e15568b87aa39005e62896ba934f5660ab25addd1cb0e26ec08289ad'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    L: 10,
    disclosed_messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    disclosed_committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_committed_indexes: [0, 1, 2, 3, 4]
  },
  output: true
}, {
  name: 'Half Prover Committed Messages and All Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('ae5d381f33044a0ea51b57c51b2519f6f1a0b47b2e5402fd5db57f2150f0e4435a20e708d39fa469187e821356316852a58a1899c19750b876585fc7840206c684d15bc4072d251997946e6b9641f48ee53dcb6372136fbd5aa85fa310a16a7eb7b2e5ebaba4fa2b3d2127799e9642a0963f976c84bd4df2f1882d64394f5e97199cdf20062ec9c3ba5c2d3b7977464817af4b34742aef6a233a54c1abc990fe547b9f087cd0bf5404b17cf5c2a0c9af62b5be415ed3bdf0b95c3ed868d79f03a4f1660e2da013fca2c237961a0a52b22044b9ed4c67edb74804d279c5533ccc599ca42d49780d9c60e013e55a77db8045c09c8b035909802a1b0d57ba47102929a04fa646ffd41b609bbcd6d2b8527d1559ba308e8872c06dc14e82c037ebcadb9889fbbc755c136a9c7d10e3048cd73c120bc0ebc3f4abbe448c7c4f515752f06e4626eacb1b48dc3c033594e3501606e23ac97b00f1bd30611ae8f5a23889d235d77a6f21405bd2e1c550421ddf45'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    L: 10,
    disclosed_messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_committed_indexes: [0, 2, 4]
  },
  output: true
}, {
  name: 'All Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b912110a83e3645dfa2de4a569808b8e2088281f45a00429aa0c4a8dcbae13a421f566d41f8b48d0bfdc6970d911a16886b87ccc69107bd0ec54690d415dd3f2e07899a737951930375d55c76e14b394536c3b8555393841de0c5227bebbbf00935ce099219dd4f67defcb6e3ba5f428ba4ebcc1995eab806f3b68d484da677f881d15c9e76f331b693a89de7846894125daf42ee6ca3dd6f3aa4d453d601d63e8f09b0d4b786f98206a513d3bd184004d8d9ee801d78eb56332ea6289c91d70cf928c8c2fa760d38179616a7fb4a35d524b30f368e7ee5061dc191deb261dee18163812605a5e666ebad0609191a00166711b74fe54eb45afc41649d4f06a336f30aa2a0f5d5dc80eb66bd4915c00fa417187306abf8d5ee20603f5c9dd6d31cb120b4a95ac1e3eb32558e5e6aece931b94d532d7d7d5c5ca9f2b8239d127fba284ff9fb0e091c1d7dba7f928dd497f6f42a2f9a9f12cdbb50b62fa79aad28266ccb04378fa6c0f0a580846d6ce1e264ef96b46bb2c34110301e545933e51e4eba9d5092e3b158d8a412e52c3b260532173174c4ca43191bdb8a8d97225c074c0f0799a724deeab447f101ccaed1df50b08901d5522b3ec561e4c4dbda9f257b8dfa584efb6d6ed437bd6c8bd80aa59'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
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
    disclosed_committed_indexes: [0, 1, 2, 3, 4]
  },
  output: true
}, {
  name: 'Half Prover Committed Messages and Half Signer Messages',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('8c351e989532f6b0e9c4992d7696c73c49a2e70bbb166fb71f2ff8face46383725c9f4667cc22da193830fdd0dba8676b0fa5b9366b8005cbf6835c425a87e3cce620572d609519943855ed39a67943a71bd4f37726c78451fe2f1a9772a31a389bb30d3c88ad5603db31249880fa3288af95f6767907d1f80590f0049637e56444c46ddd967866df8db33abae2fcbac1594a8282dbf0bc1ac912cde52643977554c57fbbbd154081093de13f10097e4707b62b4d69617df3635def324b9fb5e7609a21c73f1076df97f50a7affe23bc1afdafde9b826b94db01d5ea99a70a576a5295af627bd44e62141305bef9c076546469d1cda2bde227cea9bf01fcde7cfb1b69701cb332aba22214bf0f5cbd2a32a9e8f694a2168157407d10cfd99b9f78e928c3f0d9f2946ada6bcdf1d1a60717dbdee1cb372a80bfedb3d517b6814d1e41e65bf34b1f947623db7752fd86c33e419498717f964e2570672b781266b59acb7b67bf6b104f0735ab9f10b23604166b47d6d398d3433a7760bdc9c14e4c96f0008d61f8f522d0107b7eec8633260de697afa05733d0e71beca9fd9843139a9920c78e3efde8f837125f1ef3a2342502e26d8f53622496b7a96ca5126c9f8db04ef7dd1d631cc91358cabd54027624aa2141fb9043ce3a5f9225f0ab3437ddf4c014e2abbf665b9cef75ef1e90ca47d6c72943e03023c946387c005e3822febfcafffa3c9c69a4f23b449c957825'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
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
    disclosed_committed_indexes: [0, 2, 4]
  },
  output: true
}, {
  name: 'No Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b3d9360a36d11dcbb895fa10e733036e7f9f71a86f0adf35f2bfb4feafe8a39fe07732d05d794fa5e9f20a84b1529c5ca2ce37c3e30aaa1d40ddf00924e52e4c205183624538e3229a91661e6a69804c635f169a3f13f2fd7ea20f54bd6160948e19db59bba448ac3d7a6603af3b3849b5e2ac73f33cab2cce5261c4539b4f6e5a1038f17dae24bb20cb084d0229e377532380d9d041d30275ac35ca8f0c85ed2030d7a7a087740fb17a3b726d09bbd56567d56a51ad0a647bc9cacd891c18f07e511186992b900e0191e9867b5b15045cbcfe57243ff74a7ba4ee8941240248e6f79990f81cfc98ac88b90180de294049b55c70bf72af1283aa8d64be6ec351bb3f43121f61ac1783253a9905d6b53530513c09315bdd04aad5643699f68bd177e0c8525f4c725db1677b0046f84bbc29fc2d8170a012c531b4fd957f3f2fdd98820658b0e631eb4bb537895b0c6d6669c8e8c880df40bfea0a8cfe8434a90e8efd9e8e474e31a91862580630de574001fd07e404bc9b8a807cfa03f8bb03920d4535abed66b26bd16b6882a91c3147098d53c09f8f7dede107a6bdab8f67c5369fc56eb5f2bf90a3cb8ce555ac5c4b641f39867778f6d5e27178618091d2a2319d5a91db12da0b897782775860f7b03eecd5a7770681d348acf245d0d4c272fdb67358042bfade36b1c76640f05fda382b795690f6b279b00add5e7be48c5e606e23d1829d1f72391249023671e37d0cff4e7317d5a1b60542f04d06db8d273cafea3320a04c3c9f8690ab57ea80b7274c8ba8cd00012cf79abb154f66d63d3172c37870603e428843c5249c6c3f0e17f2679ebfa99e4d2f7a873a9f59b0e51417d91242331e1fee078cb55c65d4cc'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
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
    disclosed_committed_indexes: []
  },
  output: true
}, {
  name: 'Half Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('ad668f95a4be5360e4f2f8ec1ad4b00f063b789f3b5329ccd2d99c977aad877e3c36eb36a1eee6de485017293453513c8aa711894f40c925c0fd346f2d3504cf143dafeefb1b80537868c0bd6805f890d61d2a35b498f397602ec2fd2716f2778edb30bee705086a460dc2a2e9fb566cc5b3196ddc90ecf1e948ecc37befeff39e978b0a4dc5f08e44351c6fd877dbf91a1afa6574a212cfa01d16659e0b1229aa8d8f03d6b2dbb64b8d8153a6eb48bd53b9afcccd3e0acdeb20827f2b7a25b08fe8e1667cad177c4aef6c465c4defa71d4cb70e106a7fc9b1f2fafe44eb3c268714e4b43bfa7f944b2786830c4e6b743a4bd51a695da6228dc6f9d942fd823536e54f80e42604e4ee7a270c43e26be343560e9f8021eb34ed8adfb54f9f7e4d1b4803696653e0292894d2047b75a86339e6238472556c4d896adcf4f2170a41afa41abec1aa98d912458db314d112714792ed6c037ac8486a734580d1b89e60b371357fbf00bad30b911d330b7b544653a91c34a2bd8310849af199a591066e6ae586e14b58ca7b5d0e6cdb6c020006693fbe9acc66513544eb56fdb3d1fd83a0b8277cdd9d2bf1ef810e19ff569c4224b6f9de5c73062aa974506f8e6a54f3e5a1cbb889b0ae22e72207fae79e83103af70d3d88599f9c6197cad13804a4fd2986e7e113e75cf4774df86270bb249c245c6a2bf5f5a9971f076321e9c472a8382d206dbadbf7f86362a6908005ad3920d132dfc49c4a95ff2ca2b6c69d433338bb5046ade2d17cd18f95c4f1e448341eebf78bc73aec7f5f5a547eb9953663afb4aab2b82f9dd4ed2fc45bbb1f14bf35173f0117c7751ce7c374d556fb528995ad82385144a524514233cc841746e21ebfed48bcda634985b63facc07b4534679015c8d622fb8cf3795ab5e709b74421c2f3626751b1f833dcd77252a3b0bd09cd22d0c594eb61aecef46aa27f2476'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    L: 10,
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_committed_indexes: [0, 2, 4]
  },
  output: true
}, {
  name: 'No Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('8d1cc08eaace25a47e97b0f0a1eaf6a748aad4b15d2a769056b520fef96e0619ef6be35b1b5ed5097ef127ae2fb950aeac675419153a7154204e29015963c22a9e8639b731989e336e9e0777dc534face34b26d5db97d6bb0ac29d9d1a97b419841174ce8b0c2f0e4d5cc1dda2f5ae6ffdcc9c40d0cd7b7e8492134aa7460b79f804235bcfbec9b8213aee93243de6c1066ff92bbe9ed5a5cb904757c40101a0a17a6f2cca72697993833bf488e346ee460744b8988734f5f9232d79c5a8821f05be4ce9099e19b857dadd287b55f8a202d76d918a000cf256f2d0a145ec71ee17c514816148230126a8ca71d8de486700f538e6c33b7c3ec16b85a43eac61acd7e98cb9e6c2ced8cd4552c1653c650705d102f436a0292046bf6c08b4ef96cce2ec56f659592edf9d8a082c682ad9da31cfe12ba6c9f21eb23c7d4e569fabec33b677875db2c17dd1ad45b6973d6bfc09e551a7f2204b20249314f1dc2e1bc099c25a0396f980acb3613449be4f8e0a5a197b565bb169e15f91ab93d7d04b3316a16456d74f6ac9b05a6c65213577335cbe98fcde5747df9ee17986d82014cc1db15a428292dfe6a350d1f7131b2d4d5092d784ced5b0a0b3d5bdfecf03c9eecf9e5aad0d02a92ee9bd4b4cf69c328563fe25f309347b69376ef47ad46ec6ece43bceed9664ca919888bdaf1162d7f3523c5616b335377474572c95441b523d34ee0aff14869ae71a51caab12887bef22c20c259a7ca0f79f60bb0a8e76ca284ded334781838678e412e5ff79d0fdf3629e9259596e871aaf589d57cfde517ad672c126d43c89508763f9573b5b98ce113d511eec39e99cbef97c87921148616eebf10e25c1fbd5f4cac6be569d44a746fb1a85ca99596174bcf61df0a3cd78a34c601df931fdf29c2fac3d02a0152c5c6338a328ef725c6db9eb7ba3e1304168d280e6f861766772e37a10a2ef878d67759f017a9a7a7aacff153b18c9f31895d56c764d5b1e7ff71cae7ca5dc5d0142a751e24ada65b68f3b9dd6820a198f3ea04731ef24399b9121a9aa856d90b45dec193d1518e13ff54a77765c7c3438c72a155e2fe178222fae1981fe5818bc'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    L: 10,
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [],
    disclosed_committed_indexes: []
  },
  output: true
}, {
  name: 'No Commitment and Half Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('b54ac6e1bde3f3cb16d939774db0678f6ca4076231ca919cee3284b75e9c58773d0e13952d9d12863349551a198596768b998049451200915af5a577b1d88401487920851c4ca66b15c1b23430d99edddff019282de51cf2aa475de61ae2a4ad936d649f19d0e85a19118e5e13e2beabf2d705e1db59f8945adddafc77310b0a02042093a5477d9efd4a98cb2fad4dc541dcf9f7f6d76be6702e148175465a96ce0544b6f01aa53a99c686313a12155a3ffa17787b0fea91ce58c74d7184f4ca4c0826ecc63e97b29f6f17672a14cfe139fc8043df0fe2931c4045cefa53d0b80233838fd3f6059cb6b0138b56c1d7db18cc3b3cb687bd8f88f907530b9f1a640ef0db8df8eb7b39835874560f4222995d47850de322c7ad845d6eef499848d16fd5903860de2e955792f9914df2d4da32e2598e45ae4b0d606f77599b4b12378b8fd2baf899e90258013a7fec685c550e163a988dc15ce35a3d2d4ffcc3e897baa42ff39e4dd3108ba4bb82d19b3e4120fbfaed85949f2a21b4ba61dac6403f71ae52ff26df78bf17bbcea8670363a3279717a2b1e1d34cccfddfe9c8e3729f6e92e28197a09459c6dcd56e3920a0d74418e8d35e4956443a5e4e33d3341a5aa93a817e53e6f05c84e6c432a0e3ef29'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
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
    disclosed_committed_indexes: []
  },
  output: true
}];
/* eslint-enable max-len */
