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
  proof_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_')
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
    mocked_random_scalars_options: {
      seed: BLS12381_SHAKE256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 2
    }
  },
  output: {
    commitment_with_proof: h2b('b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4ed9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d419406945f1e79d4be58dbaf9dc95237c951'),
    secret_prover_blind: h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249')
  }
}, {
  name: 'Multiple Committed Messages',
  operation: 'Commit',
  parameters: {
    committed_messages: COMMITTED_MESSAGES.slice(),
    mocked_random_scalars_options: {
      seed: BLS12381_SHAKE256.mocked_random_scalars_options.seed,
      dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_'),
      count: 7
    }
  },
  output: {
    commitment_with_proof: h2b('85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79'),
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649')
  }
}, {
  name: 'No Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4ed9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d419406945f1e79d4be58dbaf9dc95237c951'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: [],
    secret_prover_blind: h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    }
  },
  output: {
    signature: h2b('94403c30badaccf53c4d5f6a15e66c98fe021c149254a5b54b75f15fe674978897284db9fb6a8716fa17e69c80acfef45e56e7199abc42be2ba46cdfef5b30b3cc1ed12802225733183f02fc535a2127'),
    verified: true
  }
}, {
  name: 'Multiple Prover Committed Messages, No Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('82f5137b728baea7d23bc610888e7dbabdae8b6ce404d5e591608bc0d550f246194cbab590eda33dd2a8aafc0f107f0f3158d330459681d5156d65f6dbdc7b3bfd003212a89052d668935b53895e70d2'),
    verified: true
  }
}, {
  name: 'No Prover Committed Messages, Multiple Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4ed9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d419406945f1e79d4be58dbaf9dc95237c951'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    secret_prover_blind: h2s('30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    }
  },
  output: {
    signature: h2b('a4999abd5d20fd706cabeb2a44e6dd42b76d6ccfc29ac83d947351a19807e57b0d951d4b79d03250e0e84cc1204a143336c4decbbc7417060f1fc44159192e23e437fe0aaee3971ce89e901f99405b90'),
    verified: true
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    verified: true
  }
}, {
  name: 'Multiple Prover Committed and Signer Messages, No Signer Blind',
  operation: 'CommitAndBlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b('85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: COMMITTED_MESSAGES.slice(),
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    }
  },
  output: {
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    verified: true
  }
}, {
  name: 'No Commitment Signature',
  operation: 'BlindSignAndBlindVerify',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    commitment_with_proof: h2b(''),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES.slice(),
    committed_messages: [],
    secret_prover_blind: h2s('')
  },
  output: {
    signature: h2b('b80f73e22cf6c050159018539af4fd2c8ed75a7dfa247feadbdecd983e16ddb33ac5c61bfd7f17b4063a7957456ddc0b71d46e6a05b1a464df601aabf480edf17ff1d6052089c294577fcfb7b851baad'),
    verified: true
  }
}, {
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 6
    }
  },
  output: h2b('8f5edaeeba071bee79350cc4727893732842e80d936448974ea9e1628aa94703adb1c0795d1b2ec66d4b750bdb1a4409ac7e95178c30d0ca8427578368818619102571c1862b51abc7560fe1271d86a49439b172709ef7012f527f8cbaac758ab803cab84c7c19d5d4e28241da72c141f2518df44d42846ca7b5802a903bec757c83352a5789ba2d57e3686b49f41b7a1803b642118ed8acc19bdb90bcb4fbac1fc16213d557e3ffb13184c908a1b5375072cd58c4773bc9e84f65f5fb845cd4318636f91ed2c6fa619ea193be77b18e46a7760242df2ff117ba27a38574fb8ca2904423d92cfc3420f58a063703ff71170ffd1e323f667b46197f432aa9d11608ff06b0d4aae0669e0dab0599372f9645526dc44104c6e23c16279daf102b68742a1430eeae18b7e256143d17369128')
}, {
  name: 'Half Prover Committed Messages and All Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 8
    }
  },
  output: h2b('a52e00a77f6982dcac9fe2ab683073ce3f9bc195a26d721181a3dd6217889174379afb78920d43bd28210d535cf7e581ab496573095fa41f0a134705da4037ed3099bd386d29087886f746295593c881ef1a5ad19ccbcee4a6041f00172a4dfcb18aab20ee55c319e9f76f22ab565da3dc7ddfb797bd1ccf257fdf649742fba8f01252fa17bae1a59a419de5412afaf056bac7ab67ffac0ca97ed1916cb859d9e9ab5abb1a1fcfe290d19b1660cd7dc7581b3437904023dcdebdff473e1147280719c5c65338f62b5bea1d17afc0c778047141ed5dac569b761d59989b26f79c175d3cc30e18c8519c2fc755cc4965d6448f96e8dcad1d07f8f932125645570d84b9138897ad9ce402ce6cfe73dcb70554b787a12c1eb61c2a4f3e9b6c425f2ae08c5c5eb65359e9e3a7faf08e0c6a486305fc931dda475ccd443a16310d618b71d2693d3d6ceed4d6c7d643e06ac04c4699df8ccebe97b807f5912144014bea421cc7e53b82acf1188f7420a59bcad5')
}, {
  name: 'All Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('b9b86d89d9e2a9431a8c17b5ea8426448214775d354674b2a0e956c7e10dd7e0d5a1034ae733f5591eaa4bec1f3828bba1c5f4f9fa371916a11786c4d249c433f8da8cd3d8134f3539347081d0d59aa63119406e5363beac4104dbdb22959a248e1694bd75dd3ff05a40707f9a3bc9f3e1f41ce555ca811d87514e81baa6e01923520686eab039a50cb09f9bd4c227084fdb55d2c016f406148575c08b6ee6156cb3df0de1662fea2f501ed628a34f4857213f57043ea334a655e17b3710b19502d472e7f325d5ef6a64a62c944cb84f2e2500bffdfe1fe9918e78501d2fef372cb1373c181394a4ce9adf7e37831c765b0b7ba3fcbe305cf14df858204ecb9217e9eb4f99df376f4be5d5ba43dc608551a87d6b3fcfc435c71923f32d3e8bada181269d445453ca4dbccc8a967c90af6d6194f7c3d3f92b7517ef67b7c041ae7540ff9299bf5234d6e795c8d186ffdc1c418707616978e67038f823a2327f0f12b9c015c4ca56171c4116a13c91a86a732a56e7d0261ab21b38218cb8b5701f485424e7fc1e886d021b605c37d047a134563c97d4f51161ddffa6553495fef3220918c436afcb433e82a7606feed6667137f42d2323aae0fce28b89d8188168642178799c25dd6e2e84a8939f11c77a')
}, {
  name: 'Half Prover Committed Messages and Half Signer Messages',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 13
    }
  },
  output: h2b('86645a1d743284cd08b0659c0f884432de1340f1fb105a7e21ba0cfc34758d756e9e20437e318a4ddff4e1b1d80720138b40b6e3b1b1f9d86aa8ccf51c1bfce10a19b8ac8a6fe4e5256f1e2ee542d44dfacfc6717780b2e4e6601d21e194442db47d0504a29994d88421cdd33950cd46a69b7c31384b17cf98c268c0de5bafb02febaae8fbe66e3246311d80d81149e82fe87605c0e233625c108c1c0bad5ba4cce88c6c363f4180f6e18dd252c3b79d06f66513eabcca7f127e2e62c84ab727f167f5732af269619f0f78a279dbe98653a70f99993f65d38fe6f180abf9286cb975b4ce6834467d86c5ec1a1ef4e8c3391f30e14b16a7a6c96e38eef5834785be198207bd5e80213ce626c72ca4222f7281120ee67e850b79b66918863b84ab894cb47cc8729af1300e6c116fa9218c6d7e90119a4964abbddf82238bb7d35a5d4390a8879fe56c6b39427623111f391c211571cf5ba209aca019c448aa7524acfeaa7504b8fa3d0e95cc0e99e83ae41b0a8663c8a440ff3b77b50808934cb4fef2645f4d000a452e692881274359fb597aaff6f73b0a33134c4d7333adc1b501c3bdf1296d5131c497bc556ad0b280409185b1cc65dd2f907e8cb93db88ce4e52c37c02dbbf696b81ecd57a11890796315d19c9bde637d9c1fbaeaa14b092dae8d7e50343e8b5f753bbff7f1944ca366a90c03c8cf53516b6fc592dce852df5bdda6151c17c199d52cca1be066f530')
}, {
  name: 'No Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 16
    }
  },
  output: h2b('84de896fc56822074415cda24d66c850e5870365120586dfe07ffbb9d58dd9e8b290d72b649b63dfc8bc2473e77ea26dac12380f076960d8416cacba2fe2d5cbd3b381ebc7ceb94d7bf966b70122efb7d30d9232a8d33983d94cc8d8792ad98c95b9b4cf8007e45767c0d393c4f8366f5f483fffe59a457bcf33e810785361fd4b174d7a477accf0046b5cf0496617d2316579de07be03d310881b640aa6cf0b70c23178bfbefd65aa26e33dd28217e9627633d09dba0a6ee70ead27cd17c3bb62b92b68d5c434a913ce73e29359dc0d6dd8e735847e809ff1310218ba987d39b3a8751ef93e12c8ff3cfa9b1d4edecc10c34cc7d5c4df79a40baeeafd1ca1cc5202a8b4e366096d7a14fbc15a103f142ddbb490f422a4ccc277f0b0e2f82b0db214bf7b042a6b2f8901710bbc76f73034c4491ee7f652bedb5d75362cfeb25508071c8637c2a9fa25f49ea1be0ac97670fde3b36ea07c54a0770ceb46eb8913da3781c2537e40a71d99b1725fb85a672d8bec46660b40f5b8223492274412a66eda24a3870af56c6ccfde2e54ea37e0307f0439f18fa06e8ab46850707dfddeb3c5298df0cfc5fad95ef97d3c05bbef5f534af6366ab5cb7b6d54bb5e97afc31517c03165b0666281c67752e0be8d4c46f960bdc4b5bd35cf81cba16f3cbdc14eca3d870f8fee8697f17b06c02b76505250be5edde0c39c1397bbdec2b16696bd558aedb7efe9b1c3057798bb41b02265aeb737b02e3dc747ab2b974d6c79805802ec1a2c4117e9ebba0992c8d454fd2e8f16d1058b298fae0c6bd73287917e8bde4ed5c52e312cc2f462d23ac2a843477a74b3d777518a92fb4ef3b34ba3b63c5282bfc2cd617f19985858425bf2b7')
}, {
  name: 'Half Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 18
    }
  },
  output: h2b('aaf787d7c259d7acedd1294d0523586acfd5e05c9352ef3ba19147bebba3136df55cb7af38abede5736351ad1b7a967c80b662ac990335f89b5202e881770c41b6d5da92a2d997f414ccc9e0f5ff07a916eb2262346e19127baa6d63477c40c1adfad4fc36849254eb5baca5da75b5ee3574d0f4b06655b2669ee88ed7d1fc76badaf119576cadea140b4441ba3f4ed869ed74d1349b5d625f52879d09987f9a37f67b515c1c3ae37ff95887c44641db0562dda674e046d0dd0329498d78a4c04525f5f70d46bbeba884f1315d1e0e0a11d64d2d7135ac5247d66dfc755d0ceaaacd435eb379968482f13054121743b2330bd2102da2f876bf6379f7f345a6ae731aaeeb63e3a1986c7325ce5707c9c73908d5be9fa555615626dbbc3a8893046af612189b39441e42b7433ef181d1423f3df67021fc9de3fbb3a34d69a9bee7cda3db6cfea80f3ef464b9d5abea25db3174abd99e71dc0f396f14d5579556e5c11186156a8c07938cbf860ac0f45b3c235dc8b744baf5656e76fcb25020e3069fd5e9a71966118f81246b85a46c62a070a6e66132aca408454be0fe2fa4909de71fecad7c85b2869da3787d81fa1d735c72f5479b811bc8c4cbc3af332dd7146cd8f933c009ae417a86d8c3ca9f1e5738b6050be9b690422a10128428408f1399a628c89f0d2296a4402c0fa529e06729ed80f59c2c8513f7b2776b1e5750dd71aaecc0dbf1ed783c35af918099340d614971744f1687cbf988438f7f6598a3651be1453ba4491f5c6e6442c973de305c452a8114ff07163107dbb65f96fc7ac33ea89db973bfd7e5e4c3a57654b317189220a753c30a77902cd969d7e615ec7114795d42a3f3810dadc115ee67e44b29cf35181da3903b5219fbef708e73f003e474b1b8dbfc53e1dd7a9134f17b1c48119c1d708f74bc0949d4c8192562b4dbfd026d123aa296af59e1c64dbb35b1')
}, {
  name: 'No Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f15ab02449b8d375f869a8df15db78eb02'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 21
    }
  },
  output: h2b('9341832e2e6739548581a238cd563ac3f32749c2e9b3bdfe6b2c92fb72c92add1e961ce105ff9db40b4e54c4a8fd4567afaa5d76ba043383225573bedbfa7902f877a399d4eca9b78b49aa12991f5c875e1a6dcccb7901b203e1865cf27d9a75acca75dc526343fe7c0f93f546931ccb77f0e641e0c2201798fe1048163eb0f6655b337e37c832ad1ce3715c8084f0211cdf757f4db45e4a5bcabf8490f2f3b65246d0e7ee30e475cfef6349de51b637173acf28d05753dd275fc590883eaf1069e362debbb1775ccfb9b35381e21d5d5e06f74bf17819ded6ee4342e8bcaaa606363c70bc9f2b7b774edb83614d763a0f84229c99f6a33529c382c2fea6d2305ff4acc6d289bb3a576147e96d660b76058eeba1e2f0fbfd877deefbf30c218eb2eff9e5dafb65a4f3e0ce00c1ea9c734ef834dea68fd5c7ffc1bf3de96818d67a4e4c8640297a405b28285f8a4caae44d6b7b22f7afa1a9f6aeb9bb017f0ab1ebdbd894eebf5a1bd56ff3b21a2de642435935e7cb3208ad1543a01ed8473ef17ea3635d1743733253b5285a737dbd9000cd2834d27f3029b47fdafa389a56c434176f540dc39934e80fe6e1b4c210e00dc7e6b8573106fb2b2f8b772b5197c15afeeead937ed5bbd440e29e3ef6db6a60614c8462a497041549aa47f0a176caca4dfbbe27320b6f063fa1ef94fa64750f6eb670d1bd14c85bd943c948814f680c3702f5ff1cf35bb7827a43d1e85a8c57afb55285bb9d3c4315fa37ee32cf1f98125ffa662919d37426623fb827ddbc2c2da69355a9a92d23ba7aaf4276cba1d333dd96d1124e2753d08b2092a3408c19d6691443c4081593c84f05032c26c168086471f09b1906805cda31ce4a49d400679c2c4bf1aa06ac44627566a53eddff25095bdde0eb4ea4a47817e5d138fb0053401f5f6413d862679c1997439828c055c5a46de460b1eb84d077bf5b4a6f4e54296ea1b8e062a944b4678dc961b79928f6f7743d30bdb220365800508f9849b31bf2625b27b7d18cee197f2270a226872cb69ba853d0edd9245d2a4ab5bc2fbf52fe4cd4ddc5d94a808edb0ee59f72b54a5a52f2f30b1f43c169b297c741')
}, {
  name: 'No Commitment and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abc558ec1e0899c9ad878d4fd19fe9d622920684038ecaf81488c1b67c1c49a6213f62674d08ac6eff67cf02b046ce4d4a70f7153dc7d6d4cbf17dc2a305acef53a4a4557ae63bdb87226df2e28df1d8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: [],
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s(''),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('b253fe314909bcc37d6ead780a45928b897b861df3ba0f2c17ba840a4e217d9e8012ae2592071bdd6631c11b9976bcf691505448e21f8eaf2203dcc1c420b8de04b019ab97500209344625de28897c7ef3c53b9648f26ccc664c960500425b5690e1a97c1b0d339107ae11f72cc2662b304b2fabc7fc3b3752d85f831873cf2ae01919569fa98f68182fa99847e4e7164fc6c351dbad13920dd6305222ad828dc1f2b3975b5ad7ceded3eec02626fb0402f777334696b7bb08a554f354ae1edb98a9b19f1779ab5916d3358047e9531268a774ea28faa6f59bcafca49c0aec12984639770aa4538ef169b0185c6356e55f1e9bee32b3b2c591fe33d50b4e578c80ed8e17b5518f4643ff6083bc9b76f023e0ab9422bc613b7f880da93a1601600f1f4cb7edd0ac8013099fcc25685b3b0c1530c32568059c27dd07555d044488a5597e1696c7890810ca5d72c5b12baf5b5344e6583a7d11f827b25cb825b62a1fcf038962735dba259f656a97fe12063ebe486df17dcd7893ef1ab894a50e9bb4de1b223db65e88e51f4371d8d8350265f2bf6e3dcde2dece63dd45ffcdecc8019f04664cb245f45ecdbc945e8a47723209efc268ab0e1f8266a1c283c91434fcd8c149ac811b1b34677495c7ee0a79')
}, {
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('92b9f9f19e07616a7933ca8ef4719916a7cfd27bca4081b3593313237b0d17e505ee2245c7ebea6dbf11c5ff00796af0a43965054cb458805d352b8ea04459eb9ee9c194bbc94eb89c6b76fd95b5892df98978f31aed49a4a89d1a56f71e17bea5e3790a19fa6cdaca1154b5f2c7113ea3145225ed6fc49f04593ae3d5accca80949e5f24415ff2a99044bd8d453891e115e93cf7312481f87bea699ce95b96136dd9715de9d96a5204baee35610db3d5db4dcbaf18451777f30d4dbfcebe6da1f04b4922f0ebcc71fa9ea2568d4e3081b9fe25f0e9d1dcc496d45a6736ba3330f8a1f3f33b9c8256ccdaae6ecb73332091643100fed2d0eda4c55948c8ddf38682430d5276235d294d5c40faa920bd66bc956d4f9226588d302787eaf442ea79364ca4cd646927c1b752567e8c62b75'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('95962116bfb3b9b2de1018579e9fa17b90c1b961ab665b4a4f006540a068cf432a4b681bf2ed60ad2722a8bb95721aa0b440cb1fa03c5260e3e1baae441f73aa0dfe304e156af3425cc8ca0b59ecae2be09d8cf4851b2ad6e11390703a86dfc08fc29e731352a3142ff72cf153a713f7639324591cf6108db67ce047a5aa19405b56eee355ae091dd648e4b03f25d43164d59bbbca99b525289657aebcbe8ec1de2c7d4f277518d0aa3caae96135cd3f388124edd9d03ec9cd333113f57d19c5886cbf36170930b54d569539276dfbeb5f5e34e0e93edbb440841214c38170c9ee7e60a943b290f7db8d2e09f64dbb7c3ed7a698774a3ea3585f698afefcc2b648295180943654cbf6a43da1fe190bbb661f79ee3fe448d681fa6257bc9770c26c87feb52a3c3abed0fe0272715f993e54632136c16ef6b8e87d69a54939a7508dd26ef82418fb6636ddf84482008b8e3109e279a97ebd2b1e25959cb0cdd63004706e16e66a53fe71c6851052da0c02'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('885fc9be8194a72628b0a75828b6f2297e0ac0db13473d8c8346f3862926365e38a5ab28265854a2a165fac412d201ca937eb6e249768e52c4ec15c711b8a4c2153b09caa7d64c5e010fc05f3f6ef3865920e877365f82d0400738b65f9bb421a8e4e5f7bbade675d55eb91d32adf0eac29d9dd1168acf39e89824e7b83e98381b47030c5e2ba4b9edb7b5ea262b01310ae1bf7884d2aee023504adcd48ed1c4312fc401618ab24679ca46c448fe478227d0bc48cccafe0d61b91b01bd9e9821842af129f3c2a5c877fa9c759f81b5e8606cdec75a7af1e99c0750394e8fb39465d07fb8b6049d8e8070fb1523fd6a1d052c2daaf7bb42d1187ef6efb12df7c0b9200a7230c377767289b7aac236b2f703b0f2d0914266cc0b1bad8f21330ecaee604f49d494befe28b46d6dcf2de82f73a3d4e82d628097aa773063d4e868f25fe6544abe890b30b8ae08ef22cf8529498d3e7fb7c881f275c56cf57cd19039a4189fcbd718bfb6b1e7de1274008d331fdd48de78b047b98966dddb5492c9ef093f1b7064d6453615ad0776f131794b52c689527d84d67836a61e993b8416299020a8d57bd5266043554541d0d30bd3464520473549979cbbbe5172009ec1078cb039167b018853a3a507b8babb617d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('8e1434019ae87246297e159aa75f43eb5f394576cbaad9dab7392a57841d903628c192583963dfa3c6628aa234e8aa3ba3c45b324a40223cb35af21cd4f643a97efb3262359f0a0ab3606209030eadf2d59f404f67bf17cf9eccc2483e540f68b8fbd18a6f55110fbc12966916ac698ca7a6c8c7ece5818945bfc5e3bf32387d64e532ad32f432133dcc676c2926246f2ed725e744242940a383c33e1731f366fcef24f6376615bcfc5c1bc4f29fe91553a8299ebaf843e32bc97c5114d3d297e61bd9ebfdec31310650a904981c097319785f07c63da13ff11c718c98b91cc0af9f0a1fefa5c93cecc9884b15f467521b7495b8a039923bc41f39a779da0b06564d7db558b0576ef29ec29a5ed785321f2f77c3620143044683449392de8349b4a4dd430ba33a250a419eac1c06a80f014a1f509a4abe09f4ad94d3e0497d0377fa855d222bbebf928f8b643f5b81dd49c664c48342d0fb5004ed381ed88d0d98790305fc420c2e67afc2be3b1272c217d8150dd9c78cbed8476d9a83ec0fc84c3d1ec69f6ccdeb4cca78d2207086943f76defd1943a5373fadada7e52e45cd394d3a3e9c62eb504a30709e8de25e340baee1cf06bdadccd4f6f1b1f1ab72dd9a7cdaf85507891bb446e2e483d2f0d53cbd7aa1417b01f721e149b8bdc8e0c54692ef3e136d0b363e25a44559e2c8fb28b941e2f8fdf90ae1fed6a1209cbba29fbaf607c9aa65e705c9245c7b3a2fc9'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('b49d202961fcd847f07546539dff3482d874bf49230d9195842d8e7d56810909542f670c77224652a06426ec23fe8aa7af22a741f60c494b57e511b0e39bed7690187f0dc60aacbb601876c995c7137b26a3e00929ed9f04db85dd026449bd5c8511aa643200708fa241b82fc9c3ad43f4cb7ffb8108374bd80a104276aa3b25fd99b4a39648bd6ed9d31a1dd99b0868516a282ebbb7c9e43bf4e8d02bc2661e42cd9ccf8201eb363095fb8c99289a2a4a4250499a0a58e9040724be294e64cba78ac1a770a5a6825e83c6b2d190a7b54c069f0c67a72a9bd8252e2c76da8a0c736f94aba59ec8bab63f5eca2adb55403369a441e5e7da8898ebbf5d9136ef84d706a44a14fb3e022862435b3ad9f7f4316d10d68a7769dbdc66a3108bfedbaa1cc4d97af2ce2118f4ee87c2e269ac40135a07cf3286ea1169b657121b44104036aba5e434d086cd4684a914262ad8e137ce0aac45fe18d907252e145b68482a7e9639801fb73c20b262e58ab63cb49a30bd9529c968d145facc8bdd1f8e0e29a9502832fbd28812d9d9ea58e6bca8125ec7b54f4cbf7a3a49b4eae96627b8a800a840d3581f7d61782d467ab4fe9bed43377a53c19b02c883abab17c089af3cfffedd0c3fda7523e829fb6256842efd4dbad7bd23e6fa424358878047a76e5c10dd9eebd72c58bc1a0b28bcbebbc77a45f145871c9e45939e5fdfe8cfcda8cd7e7db06ada9062efa0615bcd8324a8a35498be70cebd3dc49e0a5021aa62dc75a7575cf72aeddff26bd0ead27dabc18e31c0bfb468e8b9dff0b6c3222ad18d01c654526539f5c3d32ffe6efccc951875430dc2408bf61a1c780d89325e53943233336d878147a94e965928e430a35ebf'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('91316c2d47546e7eec8b974c58764d0002e9def61a4631f12e74a643a058f6aa95eb27b1b7b319635af43da84e9a104080542f0d9f5fbeacdc0e669d5a2e0678ace2d258032ce6ae4e9c7ad35b4739ab3aaba3a2592fdd3af1fd70fc4b31ba8f92f36dff7f48afd0afb0e1ea9123b0a1d1387f16bfba16d4e48f28a78dbe6a5c841c6ef939c268f7490f21878d81b39f4c2388ddb5e1e205cb4eda73cc830f415c6098325ba77739fdbc5a28d557302d591485fb5b5337ebe77cd33f1aa83daae47d21ec993d8d75a8956c894a6e61293c95bd0d785a0af5debb71aad8580830eb258f6c8a68810505b4bfe8c941d36c42cd81f3a40e2784ca64cd10a08e85cb9d7f6ad9dc2cd2704dd6cd31ab95f1c5123efb704c5061c1fdf955890414b43eafb2158ab7324a3d550349969fad60a52c68b3cd9e8936de4e602b92cbe80963ed614c8f2ee498c460e5ae4bb521c37e58a88017fce41b8ccd5f18963f3a6c4aea75ce64e55b578d5b41f96f24220269139cde310b9cace17efd7237cc9df18009b424c6af03e955b04277ad89fc9a0365b0fc1391941dd5b87fc95fe1fbf935d989fedd5f0cd9f684841e6b06ad8dbc64d31315fec28a0de9abcd916e6229470434e471e08b401414067413a9e45fb206248b295c6496cb025221e8f1967f4e77fc2b3b26ea02e5f1fcb0e05856c6a251b3e7ee47206c622ed321523c04d0f65eaccb1f68323469efd34d8c4f6c052a30000dc810793b0e74476002d34d8d509fe2d4d57315da6b7cbcede917446d1e3614cfb22a47a808865fa73487253c9eebe8a8fbe72969bc36ad4f895068bf2818031475232fe085bb49e501a6bb202b1ab5a5dfdb8a1adbd31992aadbb0720d4ffebc5623871fa60c35e6ce7b403a7fd564adb8ca4e913bb05ce2418232a7970a6b38833021e0813d96cc6415a88b04aa0e5bb3640ca0dc3815e75449517ef2'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('8b3f43fbbf9649ee4992f8f9659261229ea655edcf678c498387eb35b5a1bfc9a6e75c35a0e278bd287dee634ea7ec999283bee904996317f39fe21acd540d54d5b059a03fe710c3a7c7458903f1ce7f571f24f8d0b4c33e8a360156da17cd2a88ff88dda253a3514af6af70b8ca6d70b1b90ffe7a5f1ae1f84e0b5b773e03d7bc3e6c802a908338cf2f4f9a4259472526f4e747167f3cdbf2f715e466a9b7d08f3c7233f217b619725b6c3223c7b84c377876d362203f249d66cde6896b6cc60a42f853dc5ff3da5a07fb84d58d6cf97171ef532345c47e174cf361f02d77b9d8ab6a071841fe9b43eea903f2deea9a2d0a8a31d838682699132b1bddf9f3dd47fca6888f74551c7cc0a11c65330a5c05eeeb95894d65abada470d07712632baeeb40394aa01df3ec04032742d3bfee0cfee07ed3842cbaf27b31a45f95e8435fa4a571ee0b417d264c62170397c4e04844a32d9b5688e5b94e1f62deb87394663e5c832d8d167ed7d45fbcf4eefc813f542cd9e9e4802d9e80ca56a60fe06d86cf22d364d72e1bb0472d56bc80796e6f978707e9b6d67bcfafceb5f57cc6a41b30b9f3c64871af1f97e0ad28edaf905b9f72035daacd33e1535aacf2c44224f49cd6eb3b8d147a771491df19452f8139fe077219bc39ee073e05bf80d6250fcae0da2cc87df3e9998ad9d128ac6f5c078deef38e1d0b08ad4cb9aa14bcbea8520f2bcd0944a645b9334d73a1e0267a62b76a822e09754a749c4f4bb10bfcf0749dfec40056e60396a19c742bcb9bbe620ba677d47d28ef7c45105a93d4c61af612349ac323a6da07dfc302e3e42cc13d623d9d4ec6327efd0e94fa74bd0395ae8764846f75127f107a939dec73ca9201b1c920736b6c79bfae80d5b540eab88696d9cf2b6509bdeea769f6ee6acc0f5b641d7c0c4f10cffe8a5c40f92a63806b04e8c7827a519ec775080a5bad7a4a03fa6c4c7086176a0fd26ee56b22016af620a0ecbea6b2879dc8abd8844a2b8a54bad1220aa8ffc60313432d41fb9e730312cb8035d6200110545e919dee73be05732f303b6e7b458cc70e9a030cf9cad455a05707d0458785acc59bf834dfef'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('b253fe314909bcc37d6ead780a45928b897b861df3ba0f2c17ba840a4e217d9e8012ae2592071bdd6631c11b9976bcf691505448e21f8eaf2203dcc1c420b8de04b019ab97500209344625de28897c7ef3c53b9648f26ccc664c960500425b5690e1a97c1b0d339107ae11f72cc2662b304b2fabc7fc3b3752d85f831873cf2ae01919569fa98f68182fa99847e4e7164fc6c351dbad13920dd6305222ad828dc1f2b3975b5ad7ceded3eec02626fb0402f777334696b7bb08a554f354ae1edb98a9b19f1779ab5916d3358047e9531268a774ea28faa6f59bcafca49c0aec12984639770aa4538ef169b0185c6356e55f1e9bee32b3b2c591fe33d50b4e578c80ed8e17b5518f4643ff6083bc9b76f023e0ab9422bc613b7f880da93a1601600f1f4cb7edd0ac8013099fcc25685b3b0c1530c32568059c27dd07555d044488a5597e1696c7890810ca5d72c5b12baf5b5344e6583a7d11f827b25cb825b62a1fcf038962735dba259f656a97fe12063ebe486df17dcd7893ef1ab894a50e9bb4de1b223db65e88e51f4371d8d8350265f2bf6e3dcde2dece63dd45ffcdecc8019f04664cb245f45ecdbc945e8a47723209efc268ab0e1f8266a1c283c91434fcd8c149ac811b1b34677495c7ee0a79'),
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
