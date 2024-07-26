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
  signature_mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_'),
    count: 1
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
    h2b('b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4ed9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d419406945f1e79d4be58dbaf9dc95237c951'),
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
    h2b('85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79'),
    // secret_prover_blind
    h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649')
  ]
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
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('94e59d341a107330ebee0f7022bfe8639139c1383a945a9371fbc3046f71cec86fd6528d98b7ba388da6394cfc4ca62645cba02f83bb6a6c3ab736d7e45f60fd7506d28ee86b7e2a1c81cb86d4acf722'),
    verified: true
  },
  debug: {
    B: h2b('96d691cae20b5089b65383a1a39e33efef0e00c5a88d779af0895daddaad1f79bc361ae64458b69db1741077c9b63e54'),
    domain: h2b('48d64a62d7dbc8d88d643f15b3c8a1eed78afe3a80bc3e41bc2f92257b25f6d8')
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
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('86f46e9f656965c1f88f5f58243127ddc37fd38f4edba8e1d111d0c0aabaff1cd5d10b9b918933b743744b61c0ddce9e0764552e596674db723e7234233c7c97dd14270c7a0fffc70ef65b2e1137004a'),
    verified: true
  },
  debug: {
    B: h2b('b7fc207ed2d77c2e4058acf2ef5f3b0b4ee822fcf8de0a5fde095db175fa8bfa39af4b46fc9402cd9cd48a60be77c57e'),
    domain: h2b('3600988bb64779f01c57bfb0524521bc241aa0fdfc92e1b892ac2066edcceef1')
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
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 2
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('aefec656164a1d429acf8d7f1a7daf1fe2fcc959428633fc76748d15f4515f2c1ff7d26a6e784b20c743f9d01c8f73d51fe9585124b79cf0122ee58acb41e0e1e6940af4ad3eab5fb63e2438a946be94'),
    verified: true
  },
  debug: {
    B: h2b('b5f5dfb257702b03b05bb835b2ec5be89f17a490e6b0a3c0fb5f47fb0845c84450533bebb5921efffd48417071ea4c46'),
    domain: h2b('62638964b2b8eb67c2635a8b87731e2f876e7e84fc4f051903022a731c5fe3b8')
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
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    verified: true
  },
  debug: {
    B: h2b('aae3698e7234be35ab7310270e9ed3a9f000b5a94ad3ea0a2d5a8677331de7dc806a0ac97c94f76a508b85ac386655a6'),
    domain: h2b('04ad1197bffbb54ae41c1d43c61dc29325c2dc771d5cc7dba67907b17f564a04')
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
    signer_blind: h2s(''),
    commit_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.commit_mocked_random_scalars_options,
      count: 7
    },
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('823d5849764eff90d9d57252233dc4b2a694224f90d56cc81bcbcc0b3293096f3f4fdb309e06c1163a47bc61b681fdb149bf605aaf3ec89d0784e3cca39500d6acd0356d90c8ba6bef9ef6960bb60be1'),
    verified: true
  },
  debug: {
    B: h2b('95e018b5b7fe84bff803e829231870d1dec64608083a6a7b4b8f5be66ee9a6e25a6d067f528e48712528205ae9cdf340'),
    domain: h2b('04ad1197bffbb54ae41c1d43c61dc29325c2dc771d5cc7dba67907b17f564a04')
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
    secret_prover_blind: h2s(''),
    signer_blind: h2s(''),
    signature_mocked_random_scalars_options:
      BLS12381_SHAKE256.signature_mocked_random_scalars_options
  },
  output: {
    signature: h2b('abc558ec1e0899c9ad878d4fd19fe9d622920684038ecaf81488c1b67c1c49a6213f62674d08ac6eff67cf02b046ce4d4a70f7153dc7d6d4cbf17dc2a305acef53a4a4557ae63bdb87226df2e28df1d8'),
    verified: true
  },
  debug: {
    B: h2b('8ce18ec220f427e23eced9bc5d6a90bf242941676569b406a179e7fe8a3d1c3ba7fd0271ce37817876e55fe1fdf598e5'),
    domain: h2b('62638964b2b8eb67c2635a8b87731e2f876e7e84fc4f051903022a731c5fe3b8')
  }
}, {
  // FIXME: duplicate all `BlindVerifyAndBlindProofGen` and edit to run
  // with `BlindVerify`
  name: 'All Prover Committed Messages and Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 6
    }
  },
  output: h2b('92b9f9f19e07616a7933ca8ef4719916a7cfd27bca4081b3593313237b0d17e505ee2245c7ebea6dbf11c5ff00796af0a43965054cb458805d352b8ea04459eb9ee9c194bbc94eb89c6b76fd95b5892df98978f31aed49a4a89d1a56f71e17bea5e3790a19fa6cdaca1154b5f2c7113ea3145225ed6fc49f04593ae3d5accca80949e5f24415ff2a99044bd8d453891e115e93cf7312481f87bea699ce95b96136dd9715de9d96a5204baee35610db3d5db4dcbaf18451777f30d4dbfcebe6da1f04b4922f0ebcc71fa9ea2568d4e3081b9fe25f0e9d1dcc496d45a6736ba3330f8a1f3f33b9c8256ccdaae6ecb73332091643100fed2d0eda4c55948c8ddf38682430d5276235d294d5c40faa920bd66bc956d4f9226588d302787eaf442ea79364ca4cd646927c1b752567e8c62b75')
}, {
  name: 'Half Prover Committed Messages and All Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 8
    }
  },
  output: h2b('95962116bfb3b9b2de1018579e9fa17b90c1b961ab665b4a4f006540a068cf432a4b681bf2ed60ad2722a8bb95721aa0b440cb1fa03c5260e3e1baae441f73aa0dfe304e156af3425cc8ca0b59ecae2be09d8cf4851b2ad6e11390703a86dfc08fc29e731352a3142ff72cf153a713f7639324591cf6108db67ce047a5aa19405b56eee355ae091dd648e4b03f25d43164d59bbbca99b525289657aebcbe8ec1de2c7d4f277518d0aa3caae96135cd3f388124edd9d03ec9cd333113f57d19c5886cbf36170930b54d569539276dfbeb5f5e34e0e93edbb440841214c38170c9ee7e60a943b290f7db8d2e09f64dbb7c3ed7a698774a3ea3585f698afefcc2b648295180943654cbf6a43da1fe190bbb661f79ee3fe448d681fa6257bc9770c26c87feb52a3c3abed0fe0272715f993e54632136c16ef6b8e87d69a54939a7508dd26ef82418fb6636ddf84482008b8e3109e279a97ebd2b1e25959cb0cdd63004706e16e66a53fe71c6851052da0c02')
}, {
  name: 'All Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 1, 2, 3, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('885fc9be8194a72628b0a75828b6f2297e0ac0db13473d8c8346f3862926365e38a5ab28265854a2a165fac412d201ca937eb6e249768e52c4ec15c711b8a4c2153b09caa7d64c5e010fc05f3f6ef3865920e877365f82d0400738b65f9bb421a8e4e5f7bbade675d55eb91d32adf0eac29d9dd1168acf39e89824e7b83e98381b47030c5e2ba4b9edb7b5ea262b01310ae1bf7884d2aee023504adcd48ed1c4312fc401618ab24679ca46c448fe478227d0bc48cccafe0d61b91b01bd9e9821842af129f3c2a5c877fa9c759f81b5e8606cdec75a7af1e99c0750394e8fb39465d07fb8b6049d8e8070fb1523fd6a1d052c2daaf7bb42d1187ef6efb12df7c0b9200a7230c377767289b7aac236b2f703b0f2d0914266cc0b1bad8f21330ecaee604f49d494befe28b46d6dcf2de82f73a3d4e82d628097aa773063d4e868f25fe6544abe890b30b8ae08ef22cf8529498d3e7fb7c881f275c56cf57cd19039a4189fcbd718bfb6b1e7de1274008d331fdd48de78b047b98966dddb5492c9ef093f1b7064d6453615ad0776f131794b52c689527d84d67836a61e993b8416299020a8d57bd5266043554541d0d30bd3464520473549979cbbbe5172009ec1078cb039167b018853a3a507b8babb617d')
}, {
  name: 'Half Prover Committed Messages and Half Signer Messages',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 13
    }
  },
  output: h2b('8e1434019ae87246297e159aa75f43eb5f394576cbaad9dab7392a57841d903628c192583963dfa3c6628aa234e8aa3ba3c45b324a40223cb35af21cd4f643a97efb3262359f0a0ab3606209030eadf2d59f404f67bf17cf9eccc2483e540f68b8fbd18a6f55110fbc12966916ac698ca7a6c8c7ece5818945bfc5e3bf32387d64e532ad32f432133dcc676c2926246f2ed725e744242940a383c33e1731f366fcef24f6376615bcfc5c1bc4f29fe91553a8299ebaf843e32bc97c5114d3d297e61bd9ebfdec31310650a904981c097319785f07c63da13ff11c718c98b91cc0af9f0a1fefa5c93cecc9884b15f467521b7495b8a039923bc41f39a779da0b06564d7db558b0576ef29ec29a5ed785321f2f77c3620143044683449392de8349b4a4dd430ba33a250a419eac1c06a80f014a1f509a4abe09f4ad94d3e0497d0377fa855d222bbebf928f8b643f5b81dd49c664c48342d0fb5004ed381ed88d0d98790305fc420c2e67afc2be3b1272c217d8150dd9c78cbed8476d9a83ec0fc84c3d1ec69f6ccdeb4cca78d2207086943f76defd1943a5373fadada7e52e45cd394d3a3e9c62eb504a30709e8de25e340baee1cf06bdadccd4f6f1b1f1ab72dd9a7cdaf85507891bb446e2e483d2f0d53cbd7aa1417b01f721e149b8bdc8e0c54692ef3e136d0b363e25a44559e2c8fb28b941e2f8fdf90ae1fed6a1209cbba29fbaf607c9aa65e705c9245c7b3a2fc9')
}, {
  name: 'No Prover Committed Messages and Half Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [0, 2, 4, 6, 8],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 16
    }
  },
  output: h2b('b49d202961fcd847f07546539dff3482d874bf49230d9195842d8e7d56810909542f670c77224652a06426ec23fe8aa7af22a741f60c494b57e511b0e39bed7690187f0dc60aacbb601876c995c7137b26a3e00929ed9f04db85dd026449bd5c8511aa643200708fa241b82fc9c3ad43f4cb7ffb8108374bd80a104276aa3b25fd99b4a39648bd6ed9d31a1dd99b0868516a282ebbb7c9e43bf4e8d02bc2661e42cd9ccf8201eb363095fb8c99289a2a4a4250499a0a58e9040724be294e64cba78ac1a770a5a6825e83c6b2d190a7b54c069f0c67a72a9bd8252e2c76da8a0c736f94aba59ec8bab63f5eca2adb55403369a441e5e7da8898ebbf5d9136ef84d706a44a14fb3e022862435b3ad9f7f4316d10d68a7769dbdc66a3108bfedbaa1cc4d97af2ce2118f4ee87c2e269ac40135a07cf3286ea1169b657121b44104036aba5e434d086cd4684a914262ad8e137ce0aac45fe18d907252e145b68482a7e9639801fb73c20b262e58ab63cb49a30bd9529c968d145facc8bdd1f8e0e29a9502832fbd28812d9d9ea58e6bca8125ec7b54f4cbf7a3a49b4eae96627b8a800a840d3581f7d61782d467ab4fe9bed43377a53c19b02c883abab17c089af3cfffedd0c3fda7523e829fb6256842efd4dbad7bd23e6fa424358878047a76e5c10dd9eebd72c58bc1a0b28bcbebbc77a45f145871c9e45939e5fdfe8cfcda8cd7e7db06ada9062efa0615bcd8324a8a35498be70cebd3dc49e0a5021aa62dc75a7575cf72aeddff26bd0ead27dabc18e31c0bfb468e8b9dff0b6c3222ad18d01c654526539f5c3d32ffe6efccc951875430dc2408bf61a1c780d89325e53943233336d878147a94e965928e430a35ebf')
}, {
  name: 'Half Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [0, 2, 4],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 18
    }
  },
  output: h2b('91316c2d47546e7eec8b974c58764d0002e9def61a4631f12e74a643a058f6aa95eb27b1b7b319635af43da84e9a104080542f0d9f5fbeacdc0e669d5a2e0678ace2d258032ce6ae4e9c7ad35b4739ab3aaba3a2592fdd3af1fd70fc4b31ba8f92f36dff7f48afd0afb0e1ea9123b0a1d1387f16bfba16d4e48f28a78dbe6a5c841c6ef939c268f7490f21878d81b39f4c2388ddb5e1e205cb4eda73cc830f415c6098325ba77739fdbc5a28d557302d591485fb5b5337ebe77cd33f1aa83daae47d21ec993d8d75a8956c894a6e61293c95bd0d785a0af5debb71aad8580830eb258f6c8a68810505b4bfe8c941d36c42cd81f3a40e2784ca64cd10a08e85cb9d7f6ad9dc2cd2704dd6cd31ab95f1c5123efb704c5061c1fdf955890414b43eafb2158ab7324a3d550349969fad60a52c68b3cd9e8936de4e602b92cbe80963ed614c8f2ee498c460e5ae4bb521c37e58a88017fce41b8ccd5f18963f3a6c4aea75ce64e55b578d5b41f96f24220269139cde310b9cace17efd7237cc9df18009b424c6af03e955b04277ad89fc9a0365b0fc1391941dd5b87fc95fe1fbf935d989fedd5f0cd9f684841e6b06ad8dbc64d31315fec28a0de9abcd916e6229470434e471e08b401414067413a9e45fb206248b295c6496cb025221e8f1967f4e77fc2b3b26ea02e5f1fcb0e05856c6a251b3e7ee47206c622ed321523c04d0f65eaccb1f68323469efd34d8c4f6c052a30000dc810793b0e74476002d34d8d509fe2d4d57315da6b7cbcede917446d1e3614cfb22a47a808865fa73487253c9eebe8a8fbe72969bc36ad4f895068bf2818031475232fe085bb49e501a6bb202b1ab5a5dfdb8a1adbd31992aadbb0720d4ffebc5623871fa60c35e6ce7b403a7fd564adb8ca4e913bb05ce2418232a7970a6b38833021e0813d96cc6415a88b04aa0e5bb3640ca0dc3815e75449517ef2')
}, {
  name: 'No Prover Committed Messages and No Signer Messages Disclosed',
  operation: 'BlindVerifyAndBlindProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98699909137b16b5ebfdec7396d515f606415353f4ef0a329db11bb2fddd266900e54219da5cec913c1d4593b8231a1842c1659bc991b18e778c195540621d097d0288aba536052b1d14510d3ed165f5'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES.slice(),
    disclosed_indexes: [],
    committed_messages: COMMITTED_MESSAGES.slice(),
    disclosed_commitment_indexes: [],
    secret_prover_blind: h2s('41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649'),
    signer_blind: h2s('49541deb67dc42d5509d39548637959bc43e105fff02c780a308c78e0a1e3c7f'),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 21
    }
  },
  output: h2b('8b3f43fbbf9649ee4992f8f9659261229ea655edcf678c498387eb35b5a1bfc9a6e75c35a0e278bd287dee634ea7ec999283bee904996317f39fe21acd540d54d5b059a03fe710c3a7c7458903f1ce7f571f24f8d0b4c33e8a360156da17cd2a88ff88dda253a3514af6af70b8ca6d70b1b90ffe7a5f1ae1f84e0b5b773e03d7bc3e6c802a908338cf2f4f9a4259472526f4e747167f3cdbf2f715e466a9b7d08f3c7233f217b619725b6c3223c7b84c377876d362203f249d66cde6896b6cc60a42f853dc5ff3da5a07fb84d58d6cf97171ef532345c47e174cf361f02d77b9d8ab6a071841fe9b43eea903f2deea9a2d0a8a31d838682699132b1bddf9f3dd47fca6888f74551c7cc0a11c65330a5c05eeeb95894d65abada470d07712632baeeb40394aa01df3ec04032742d3bfee0cfee07ed3842cbaf27b31a45f95e8435fa4a571ee0b417d264c62170397c4e04844a32d9b5688e5b94e1f62deb87394663e5c832d8d167ed7d45fbcf4eefc813f542cd9e9e4802d9e80ca56a60fe06d86cf22d364d72e1bb0472d56bc80796e6f978707e9b6d67bcfafceb5f57cc6a41b30b9f3c64871af1f97e0ad28edaf905b9f72035daacd33e1535aacf2c44224f49cd6eb3b8d147a771491df19452f8139fe077219bc39ee073e05bf80d6250fcae0da2cc87df3e9998ad9d128ac6f5c078deef38e1d0b08ad4cb9aa14bcbea8520f2bcd0944a645b9334d73a1e0267a62b76a822e09754a749c4f4bb10bfcf0749dfec40056e60396a19c742bcb9bbe620ba677d47d28ef7c45105a93d4c61af612349ac323a6da07dfc302e3e42cc13d623d9d4ec6327efd0e94fa74bd0395ae8764846f75127f107a939dec73ca9201b1c920736b6c79bfae80d5b540eab88696d9cf2b6509bdeea769f6ee6acc0f5b641d7c0c4f10cffe8a5c40f92a63806b04e8c7827a519ec775080a5bad7a4a03fa6c4c7086176a0fd26ee56b22016af620a0ecbea6b2879dc8abd8844a2b8a54bad1220aa8ffc60313432d41fb9e730312cb8035d6200110545e919dee73be05732f303b6e7b458cc70e9a030cf9cad455a05707d0458785acc59bf834dfef')
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
    signer_blind: h2s(''),
    proof_mocked_random_scalars_options: {
      ...BLS12381_SHAKE256.proof_mocked_random_scalars_options,
      count: 11
    }
  },
  output: h2b('b253fe314909bcc37d6ead780a45928b897b861df3ba0f2c17ba840a4e217d9e8012ae2592071bdd6631c11b9976bcf691505448e21f8eaf2203dcc1c420b8de04b019ab97500209344625de28897c7ef3c53b9648f26ccc664c960500425b5690e1a97c1b0d339107ae11f72cc2662b304b2fabc7fc3b3752d85f831873cf2ae01919569fa98f68182fa99847e4e7164fc6c351dbad13920dd6305222ad828dc1f2b3975b5ad7ceded3eec02626fb0402f777334696b7bb08a554f354ae1edb98a9b19f1779ab5916d3358047e9531268a774ea28faa6f59bcafca49c0aec12984639770aa4538ef169b0185c6356e55f1e9bee32b3b2c591fe33d50b4e578c80ed8e17b5518f4643ff6083bc9b76f023e0ab9422bc613b7f880da93a1601600f1f4cb7edd0ac8013099fcc25685b3b0c1530c32568059c27dd07555d044488a5597e1696c7890810ca5d72c5b12baf5b5344e6583a7d11f827b25cb825b62a1fcf038962735dba259f656a97fe12063ebe486df17dcd7893ef1ab894a50e9bb4de1b223db65e88e51f4371d8d8350265f2bf6e3dcde2dece63dd45ffcdecc8019f04664cb245f45ecdbc945e8a47723209efc268ab0e1f8266a1c283c91434fcd8c149ac811b1b34677495c7ee0a79')
}, {
  // FIXME: duplicate all `BlindVerifyAndBlindProofGen` and edit to run
  // with `BlindVerify`
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
