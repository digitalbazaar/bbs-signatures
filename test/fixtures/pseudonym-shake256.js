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
export const BLS12381_SHAKE256 = {
  ciphersuite: CIPHERSUITES.BLS12381_SHAKE256,
  SK: h2s('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc'),
  PK: h2b('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c'),
  commit_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_')
  },
  proof_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_')
  }
};

BLS12381_SHAKE256.fixtures = [{
  name: 'valid no committed messages commitment with proof',
  operation: 'NymCommit',
  parameters: {
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    committed_messages: [],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    commitment_with_proof: h2b('990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b'),
    secret_prover_blind: h2s('643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48')
  }
}, {
  name: 'valid multiple committed messages commitment with proof',
  operation: 'NymCommit',
  parameters: {
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    committed_messages: COMMITTED_MESSAGES.slice(),
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    commitment_with_proof: h2b('a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3')
  }
}, {
  name: 'valid no prover committed messages, no signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('b75c2aeb0b79506a85fe900efb954ecdc591e5492c90204221371756226b3b0a30e39ee578354b7566fd1766bf1d9212424fea257ef8c483c879ffa3c2f5c9d7a64cea4770e391ca7b3a305a3306496b'),
    verified: true
  }
}, {
  name: 'valid multi prover committed messages, no signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('b4b026980b38e88dd7d89c953f8c6750352aa9235865bab030999850e832578a374fcbeb3882dedc72f50d1fc8e2083932227a61a93ba23f7fac72f587b40de4bf36bdb5567ef4721d0615b91ecf1811'),
    verified: true
  }
}, {
  name: 'valid no prover committed messages, multiple signer messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('92a8e449a715421cd49fe58433e5ed2300a67d36d589eac87536bcaab616cc846785e17449a9baa83826ee177f79445d27bdd783b7730048f7dfd355fb7494d150f15fb203f4d0aad2a65aa436ffb208'),
    verified: true
  }
}, {
  name: 'valid multiple signer and prover committed messages signature',
  operation: 'NymCommitAndBlindSignWithNymAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    commitment_with_proof: h2b('a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    mocked_random_scalars_options:
      BLS12381_SHAKE256.commit_mocked_random_scalars_options
  },
  output: {
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    verified: true
  }
}, {
  name: 'valid all prover committed messages and signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
    L: 10,
    disclosed_messages: MESSAGES.slice(),
    disclosed_indexes: [...MESSAGES.keys()],
    disclosed_committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_committed_indexes: [...COMMITTED_MESSAGES.keys()],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('87c87375d670774600975ae2cb67a08d884f1a40a0ed279d49e9f9347758f712a23b60ac21b6b210ec6a4b0e80ad7716a604ee9ef21240f4874fb365a4e7a46cc34d9b681ff02a94335ba5e6d3cedcad0e10e5b5a7e1cb75ed9b4b7c64b340729308f98ceff347fc7632a81bdf1c4a50f95347d6108a018857a90f0fb213c4cb36b74c48e120f061d4e725ef3c89f55271ac7b7e303c9d58dac01d03a5efb470f9dabde27d9a0935201f960323826aa27278bfcf22fa6094c9caf7a19e263fbfe0a1d2c49ea6db45cb82f0af71b856775a2cb6a9698360cc005b4fccc24256a5d628552e8405b082360c5b618076e86619b79d53c20f1ad73db7ceebdf80af65f5bdaa099d7ede9c043f234f6fd322364168c1e09a10a9ce109646243c70b39f8a6aa42031ba4594d76e6aadc5b3c1c71e2ffc5d9bc0f6c649c460d99b27d52f0c2d6244bf0dc1c1382e73a9782d0851'),
    verified: true
  }
}, {
  name: 'valid half prover committed messages and all signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
    L: 10,
    disclosed_messages: MESSAGES.slice(),
    disclosed_indexes: [...MESSAGES.keys()],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_committed_indexes: [0, 2, 4],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('a368748cfab5ea798707998a21db421647144f932990c63dd69fac0b2046f6f4910a806098932ca655ab37f4276a9290b05d44f6755a4f3bb1ee0647d29e81e30d9972c22b96c99434b86a9877cd97fb18b923318fa135da8162861ef99c4988b264641475a51a0e1ec8a6289db1bb555e3ce8c05a5079011411ca8a9d80b671a0df37aabb8b65df3aa2dd5db766f23318665d8086ffdd1b21268ff4f85a485be1d05fbb4740a6c9012249924ab956656037629f1ffb6790ff7e9d6fa4b62a06585c8246e522b8ffc35b4c830091a7c42b760b6035286156b95246ee177462bafe07e34599b00bb2e161188ea4f19e3f3a890b73ece45df6a71602ca3598b0c981f39f3b30104ea893e410a86b6612a90cf576c196ea2a9c31a514dbfd90118aef0598714b98d32066185be45e70cab0461715872ec7d7d08374a9e2751a99b9222f5b7d5164e039e65ac80e55672f4b42713d94b077f14f2fac74085fe3d300c19802a758d4e4d9a63c1d23bafb54b13970666b9cdd0f4ab9c4abbc46907422c2538d704a7b8ce1655f76ebb86648b4'),
    verified: true
  }
}, {
  name: 'valid all prover committed messages and half signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
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
    disclosed_committed_indexes: [...COMMITTED_MESSAGES.keys()],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('ae0e79f2e30926b255f576949b1f34a4843d061b9279732d20315c1b1e133ee19d54dccae8e1aa90d628e0b4a423e958a4b674599ce231c77c779cf55436be406c72296cbef3d46f72702323baab6197223ff60a15e67e9540dcc6875b6fd764b27df0665f39469a94270c0433c070598d11deb8692f8db5d06ef2ce323d8593d46160a43df880d624e9a64b2935651b638b586d67c809e60e7a0b5affbb5a3e6e5d39a6e3dac8d18d7ac31f9b8573e76b6a5579b3d139d1d076a37d300d7fa5bb9f406ef0ee9b23799c78d88209812e1e03306d7648dc4ec8281c77222f28522bc98e2dfe93c76e707a23a303cc50f81f3e26d2481661f9a69fff45bb93ab27743397092a4b21afb4d7d8fe6f8ca452207e85ea56bdcaa7822f032b40ddbdbb0cc4a7a0a49e72939cb60878b0b6075f31dc4f65e1fbdadf8aafcf4dcf8b7c1136d00d2eec96fc3c85bb08ceefd4cebb3e81e8c3ae6a868aa7aa388d3baa4846e97698255ceabd698814348c76f99a0673cd718d246c215fed3bf658d2eab39d387d56b9165374fd8fb6388d824d30574224b0ccc6927fefff9baa7761ee5f084cfb6611a8d39621c77d04f4252b211f0164c4c5c56ffede4146709687a52af7380dc12f05081fcb522ec4dcd6218572084934b53547e3d7b33807f770c2a6c4fb51d11358bf650ce01b0965a50041ce'),
    verified: true
  }
}, {
  name: 'valid half prover committed messages and half signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
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
    disclosed_committed_indexes: [0, 2, 4],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('ad1d728a7fb4b68de8d6ac04842bbe08fe39c4ddcdb6693415efde9565e61afa1cd095bacd7830364b5c14f505b4b6cb906de91cf57f482da1ad9dd5d9cb60c244568f09f6d30cbee78c09900a1f1c345ee43373d0beb5a4c83659ac3042fab6ac9e660eb2e2b4e11550b27783379deddad2a05528768f0306fbb4e040e4ab0402c4b96e34c6adb77c8b37f38db432a74ff95092207821daa45b30115a36d053803a71d0c61be79f9b5c7e465f53df732aba7902a9d67e32398909267866e6f3619fa1229c3c0778523f5b7d028ce355272481ca52aa203c049f3890f14793e8f744e51bd3f45fc4a7af2a5eadb1427e5b4d7064123101951dd034b723a759228ee439cbed30a4866beb7840663c825303264769801674e6ddf0781e54585929b13c4243b4299cdc0292450ea2d74ae328778abb5ac27fc5a7c1f0b011751f7e38b6a0033c565b369efa0d49d45889b51c616f1cdcdfd499afe2ca256eeb84d215fec570026b18429105dee0451a7682697c045f40d132846f1428fb1d4e403e93bd8150a597c6033f84a110dc14da045800e29cc062358ca304b1e382b1251c851cb839e59b5ecfafccc3dedbb6594920c7348026598ffa59f7fe3df27d86bb8069c10c5225c8aa8c09ebf23819838663a7474fbda2635b2ed3e829870c4fa1208497773650d6d1c315ce5df97b1de16e097279c1eebab239fd37861ff106d575f9bcb01a259aef02cff53f0a3b26e1025fa34d8302ee4f998f00214fbc429e2551dfebda5b46b22319ed8f08821da0'),
    verified: true
  }
}, {
  name: 'valid no prover committed messages and half signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
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
    disclosed_committed_indexes: [],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('a07906dab5d5d523a80986c377f6c85618875bdac8bf8bdfd35439051f98762c8abdfef2ef08cdc7a6e14beacf7b303b8094057395b26030b2a7450bd5a8766487fff98768e705e636916c928adb95a3fd3f80b83f232b18a88396bb9dd1112885192a7fa6872221c29a9659f05e7a482e554c6a9b4f5a5571938bb099c2bd5f9a29a9fb9495625248d975ebb478758f1bfad60f4750647b1f2f3c33a14fa5273c67a0542e2725d911195d9a94d7ec183328166651feaa3ff0ddf7e3394426afc1dd26fe2c4a89a2acc8c5ce71f3ca50113e7b1c8a2a8c22fe81505fe1cc944b4ea86c4dc9020661e7011231e9db581e037ebe34ae083de76e9a22cc100b9304c4796e57cc9d6f5386cc0ef16b66506c43a976dd5a104ee0ce5745cb4e61080b3b0aa25777d85c64eade558b63f24edb594ff2add441fb95d9ebb22bd807a6f96f82d10fb77fb6af178b002e81983e9e5396ab8e6c7777398370d557a1570cb4a90c3ab9bd9d4b77d475b2b10e2472632590567f0951fe70b7b62645985af9284dc234d91c722d0a730a75df83af042c4f6965f8286ec4479b102e006e463f467e7eccb5bb192bae8e52c1c219edad503d2473de89a67dd8720c31e73923914ee8496bd13743192b8b881b0c11b604810249678be3865dfd15e225d264a408f05114a5b1f3634a117a2e7e11ff7571d56847e8ff18edb02d0119049b4ccccb7634e4343ade7e788e87da183fd916cfc2111e147a13e2cc1667ae18cc5983412b936b0b3ca207134da3febd66368d865f701a22b026c3f1f457c471ce02ac90ab44c1d3a3eb65b571bddfd911a93da38a446200e6a0adce64aa23a52ca7a8e5213cfe08c8356f244391d7ad8fc8e352c35a08681488a2c99af62a6fff67798ea557b7a3fdb5087904b1ac25e1ea0c94b5'),
    verified: true
  }
}, {
  name: 'valid half prover committed messages and no signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
    L: 10,
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [
      COMMITTED_MESSAGES[0],
      COMMITTED_MESSAGES[2],
      COMMITTED_MESSAGES[4]
    ],
    disclosed_committed_indexes: [0, 2, 4],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('a8910fb960eaca764593b00202a3f062c53f25d71701531083a72acc34c3e7b08642aa58f67f1835d9fd607c93765d35b13e33dc916ccd3582410b9d3b5f0ce25b3bb8d2a0954880798251662b0707ed4e09fcaa2a8c5b35b77712ed4f68cbfe985bb1ffa92458f9a8b54b19fbba33119e46deada623a3f7e7cfbc9e021feca9bb3273151330a55e7a73a8471e4b4f493856d71fd4c4291e17dc48e75b31bf4e85878efbac859197a31fdd0370dc627454c801ce876590e605acaa176bb1900b82d556e7217fcd93ee75970e99ec0d71326a36f02944b36f043c6f93c178bd773f3271d7c813e7f8d5fe47cfdf946358401e543e3e8453964a4df41617097872c81e622849ea544210174076fea749a25481f060d4f4c8ee179da05998e1fee1cf7b2e16fbb47966b96d4f34f18eedea1b91a0f917201c2cb05ccf1bbf9330a1adf5ebd6a6a9a3d37bf1cd1f08137bad407d72d185f1a08715292ce4cc74585fd9c60c5e0e2b0b37beae01a89f3c3f8e3be9fef9a8c8c9cb04d6d6a12bca713387f269684905db470cc88414977aa238651fedfa25521a1a038f3aa1f184c062b48170cf2420c626a3f08b81a8a5948e38ebc4798bee33c93c984580d73dcc7dc25a54977dfede551d7e2b5e79bdca1b60da532dfd00ae4696004bc9d1ecf57cba492145558b7867c721a50556d937c540b5b38313120be55d43c3fb5d9b4a409ec44f62038dda9ac16f0aaf48848d2d646ef4c6cef5de59f969b42ee46d54867833f299582729a06280331e1e77cc2065c5b24ad2d8ee2b7e4038384f703a0125fa8e8e2e050885eb20a087c0cf168508b9c68d1f3b72fc7609e3b7096e6dbb7c51bfc85f4726d99e1826a736d02cd245fd76b4800f7c313654f21506e0217951fb8417afed7e462e1cc246fe0580a73daadd9e38188255ec3a8345fc34bde995bdadf3922d2a380f9c1a2a15d054f710f838acdfd31ccec8b5f53427465e5b715df435647cef473216fe38b707aa8f'),
    verified: true
  }
}, {
  name: 'valid no prover committed messages and no signer messages revealed proof',
  operation: 'NymProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('a671299573ec1e179a92e97ebc5927698327c11e2c56608e674fff2aaf2e1a4ad9ddffcb412391c447cdf09c30e8e95d1888e3f8cc0f58a170b1a4c45e21d1d41a387bcfff7275ae96b00d6f805bb32e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    signer_nym_entropy: h2s('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5'),
    prover_nym: h2s('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418'),
    secret_prover_blind: h2s('1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3'),
    nym_secret: h2s('3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc'),
    context_id: h2b('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a'),
    pseudonym: h2b('8ef7b8516387badcdf24eda35553031d01c392b93fb943445ae90979d7285d877ba6509cec3a3520f46128e97ecbd136'),
    L: 10,
    disclosed_messages: [],
    disclosed_indexes: [],
    disclosed_committed_messages: [],
    disclosed_committed_indexes: [],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.proof_mocked_random_scalars_options
  },
  output: {
    proof: h2b('8d3b51ea093c025a125c461892b18d561dd5205e7c01d5d61dc38278d45fcca8241a5fcc42a50558ea24926a6577e37597dfe3f3264cf81a17752c364e0cd355099408f5b37bbc812996533c13c27eb5649082ccadab658253d44f83919a9166a92b28c33d426a662fdd57c2ea3f84b89dcad87b7091018ec26234ec12ad9a7413cfeeceb7af93be473a95911d2d47f43df6551812412dab2de651d09d2c12b6b4536ead479bd7e9201124a963dd94913bf550b84a160073ce170a83ad5b841ec384a1316acdd647a07c4d55168105b41489e6e56033f92a57855cc8ed2fddc93be3f625490baece8e551be6491f36c145a945a24f4693602e511e03647d50b708caaf02f49eaf19cec6c596fe6f79bd18a9da98d1aae28f1bc10d205a16b241c97de75a17ff24bf1e47f063775e219257e7dfad9b87b9127f294210d51e026357a11822e2e4ead4fa1fb2f7615dca5a6bd8ba2094981c377579a2442cdfba154f41fc69330a5f0f3f029fcb5ab5ee161edbc12157e33cf37578cde84633bba1144de3a61b23886237efd56fdf5576ee3d15e7e4eca557f30c4334dbf2921bccf53ac38bf9efe620182a80e49ed9771e63b904eded8388ce34fbe47bf5417b0c9ff9dbe489c398c0c93e3778ddaa9b2928dc21e690854e283b146ad30d91117e446aeab2a6552cb1e27fa4a9ff976b0705d0b0ef8a24f62618724af86b655486a265bfdfc3d920588c74ffedb193821d006253535daaac1ab794b0033b0f88faed65df6ca145a8478c3d4161136cd72e50c40fc7a2320de35238c0c47f3737c246be00932155cfdca71d17cc8e305f6462058dfdc7e87492e052b221dabb2981621ac4be7a0f075264a4748e8c7b2a58396e193a8ea15d7760af0e75339c9e16c0deb36633f082e8831759fd48f28a835960c5846dde3b0a7b480d8a6f9c59334b0a844c9553b58ddc849a9b0d785c655dfddbbfd9d24896f93c2597f3b6dd58126229fda71ed410a6338117cbb41711738dfc6736435578e6b23d6f03aa939b4016aa995c3b56597516d99133a854130461c8ce5244caf5b23ffeebfa3b6c8ac8df1194e1a65ed740daf129a325ff3b15d12484c7e398e9d97533363068d1b7cc38676e915fbf93264c2209860e37c2'),
    verified: true
  }
}];
/* eslint-enable max-len */
