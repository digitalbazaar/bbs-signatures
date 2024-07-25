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
  output: {
    proof: h2b('b9e17ab6b187f62b1d57aa0601e837362237c17bf4f0262b9bf0c7245945cef306f949faa8921dc550baa522aee9d128b6c3195da62659efd1c3e9095a51239b5931996f0b4bd1577cafcc3c2806bba419ec9580f8e12101441f2476876459f595bfee618011969b7bc139480e0b6d8cd4f53b6dbb22718e3948caf3a692694b6fc198329c5ceb021a9aa615b9dfd9dc6ec3714ff2caa95133f83f210de4b32432b371e956fb1ef963db4f15acb6994e23fe0e27b8a92cbb4ec8c31458911a05e84cdeed70a000ebcf4b4f5e3a51173c146307866abbe87292c4b5f5b33ad3a44366b6b907519ab4f4353a44b6d8a6410b192d6d261c510dfa5d65f65fc568d101a1f063a786e47658db1d4b067897135e5b05ed483541eb523c39bd69c91ff0783954bf76c2530c6dd814857e47e81c'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  }
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
  output: {
    proof: h2b('a14083a6bcab28b937970650144a8b28819f723929aacf17a0f56b6f5e5d3bbce24fad0e3f8c76b5bad349d41705083189ae2702bc4a5b2bca322d3988d6ff35055ac1b37589897e4424c4eee64c199a8b58263466f5b1859c24f5ee0e6d21bfaece4081d36caa8b80574072388dc2d17c72558fc725de00259c873596b76654e1291479d8f79fe4594e6b86310bebe738db8cab6c33e7104ddbbce9a343eba4b5788247ba0844bce2f589839ee771eb3d2e0cc0d56b43f2850dc240161aac8c3cb4e557ec444714505c8ff8c2a231a72a6a0fb335fcba737d1f3de54a226533f3a008661279e80837e18bd81767ebd447f472600499ced38ce26502f25e842b5cce3dc4cca9ab29bab1e7ee17675e6c2b9e94552dee5cb48f73db02934946da153ee8805cb89e73941d186ed255d9033b2c68ac32a9956b38b9cb0688967bd6ae7a993aaac3047d0c6e611d2583ed5d0abe445cb55e8143822e1f243f646a56d01b77c1e3aae12567d4a90b634e8063'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  }
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
  output: {
    proof: h2b('a6056ca76a8d342646fe509aff0a0a9a473d1dd9a740325dcbcb8c2391e27c41fae3560e68014c258847cdfb825ffbc08b4dd4f6dac26e245243e77e0450a9f57b5c2a26201e628f477307e4b1ba46239b5b37789e805f4494f0a79eb58a4175b1ced5d5f5b401169891c734feb00829f62d575131114d5deac4c293134fad7f9485497935db52da96694e61b4498634723fb71bbdfb3bcb922474dadc780ccf8370f601f2313e2e133e480a397d715c262ac48aa3a5ea18c8fbe37269061ddeb5fea27583a19e8547468bf275785e5261d84cf2442fedf89ed8ab4323f6e10e337521794e056ff7e9ca417da7b18f5319e99832031eb46f74215e520190995041738445b92e42cd44eea874a9101a47477745473d4d01e259183a8b7211083d9dfa557c6ab12266982176fd94c0859d53eca062406ce741ac9ef29d79a4da7bad78208e70eefc7c1c5f01a862095c21450fdaa0b68bf5748c589612721fd7b183b0514fa72afa0a814ac4838b50a4bb6486078f7c1f289951d3e09f5970496a5d2d0cd3c92d2751f3b661bc0a7a9682441c2b29a667443cee0cca618c0df1f763c2e7b5eb622c2ce72db1cabcbb055d45c33cee4b2b0e084938f8a44341dec62aa4e673c5c0b21dc30cc97a925a6dea'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 2, 3, 4, 5, 6, 8, 10, 12, 14]
  }
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
  output: {
    proof: h2b('a96a052121e1f2782cfb286fa1652c18cf92bcf9d27da34c6e68e97ca750b4e9acc1706e7e990c3c0cdef9b7127f7f4399112948cd46ff9cb8644bd7eef9a42fc3738685044dcc36a2e512eb6931df951616a73da6647ca972bd9d975eaeb478915d70529fbddd042e0c355bef5854d05f0a6741acf8a92711baf1b62218149df20f1eb98ba7f7f797697c8c33356db12c5765eb955a5aa9c99171483921abad20f0f12e327122e50fba43436094e7216ecb0208be6b8b9db6e87421e80950db0fd2f844d165279e1f3f474a23bc81d613508bcfab50307ac704073dfe2aca37bc6e56368b39147e4f58f3f837cac4b45512551eed47d3351751a6891fb9f615c68218c4cc2e205032f29373efa4f12324283e8c4ab31787d478df1e6754bb8eb60520a3b7b505669f964fa38db5262811a7bbffec086b03520c4bec622a59fd36adfb2f55188f221361eb50d5f01f8f71e2129d60fc1ac23cc1cd44a607fd252d0e45610271c400a39932ffcf8be8f34975398e584f36e1152d8e3f9422f3201b32a18cd13fe3871bdc5a81c557a0d2586592f0578714223aabd0bcfd975f55cfa4fdfb7418966654b91abff11ab96615e883ec30b4b632c3a350cd69a8c6326cce61547267d6410757bfb323c0a0833ce279e939a7f381c91738b3743b60b3800c1aba91e7e8d395539574f8e8301d459fbe79e7c51693a959a1de996941a9fb8f3810452adc9221582092353902ca'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5, 6, 8, 10, 12, 14]
  }
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
  output: {
    proof: h2b('a46cea8d9d0f919fdc86ca3dd1ac8b2a3e2378e284ba821202cd8de28d07cf961025b3e40ea6c04a8b40ce24254638c283966b37e6d484324d664fd4b7a0902e6183f0785933d6a169a9a2317d36f5e46eaceb1ea1aa8217a8814e17109880758e42a7ec9ce182a1cdfcc25f77e5731ef62538316488e74783bbd4b2fb9670da9d65b56385bb5386795529447e0263f331fc893fd155f22d61152e20d3b61ff16b31db1e9061022f6571a677cb0bccb56d0bb7df15cbc1bfdcb096035766d120fdeff44b253cf5eca13727e1e022b0a37120ab12381a0870d890d682dea4a4dba263cb80f19cb993febcf53865709548728d35b5e7ee27e55ee188d6e8d17a3c846f9e1c56ed42e9af450d73e7ef3826411062fd0fd2496acd5961ed94136691d8782f534201c741bc4d56317825222013638dce35ab399da8f2f5bc0a40e43a79348483d7d1b92b95277687ea25a53f17c3fca6cb30ac6d0e711c89c36f2a6034d6a2a12124e6743c88da53fa46483c37672c7161cf6273bd0fd2c1226f5b96a8e5572b4b7974edd4182a96708a01a05eeae79b84cf79bed7b01c22a32a2ad38fe92cb8eca55cec5d75f9ee876a2c0f2982f0a47bbfabd68627892687bb87a5f7bbcb2819d4439f93439e2aa1191a5643ed031197c66bcc1beb5d9dc1fb24f5f452c3f97900bd42194f198c62b8caa54173dd5a76260ae41c4aca2cca8430874e575cbba47d718300f0ef7bc4676553508938f9e4cab05889a7948f364a91c351f3796f5bfa8bc36cd46d040823c33164fb33187ebcf86f20af8ba7d75cf558c302e977d86d4485492f14c06198ee784a9510fe499cf516bd1c96e0ad60a5ad07fd5bdcdcb97a1bcec2ab951a56eff6'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [6, 8, 10, 12, 14]
  }
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
  output: {
    proof: h2b('b5b84e7a44fe9c864d7aefa086af221b5635c08c91e07d51c735dec90b13a7b8377083f3fd726d22eafe2dcb89cc02b192a874481a1aa7858118cdbd7c7cba094f761cbe28f4b81c8cda6dc04cf4c4cfff481b29fc2443cb1c7ce94958de6a5097a3e15b348fb6bb89db4ce5a54281163f71e2dd5cf7b09e1d1b0474c54ac24f108293cabf24d6d3c85ffaae51cb28d322018c6f816001ad881c892246567d9e80bfbc94e2bb706654029572d10ab58f408f459c2b3d626f211b9af6cf6dff3b1bdf9c3e9258a8d79b447e30836c6f3a10c4ff96e5229acfc0c01be5ec60cffcd9b183eb27e167f7ef55c116af163f64203d8a812616a47533d0142c1fc156f253c198bd2fb31c024c24cf963b4ef8a72685c0e60fcae9a384482cf76b2bdb32cfff3e0397ee4574fda20335e7cc21b56ca46db97020bdae7f9e1e3f95b1ec0a1604eccf9d1140f07229bd1ad40db6d9504e94bc801457ddbc77a0f1c2f13896e54ab4e8542b9cbecdfc75733e8e413d6b3532148349e478219bf096ed7dad49ea049d0ffe8209646fb44401a64bf8d003462f2c93cf3a18e56063884e502c450c81c0b838b4d4642928aa741948d19b727188c92eac3642599da6c50becce73fe3d8560750e988ebd8565fd4067074739f226c9e85da6f57eb672f7bf83a2961d15b93a61a1dcf1eae7fc98968964880dc0978753deac2e745089fa56ba89790594f011e344d0e7b9803395d3a98f916c87ab9346a6dfb424a0e7280db4f7ddaecd99d87a2aa59e68afcca68cac2fa516166185a9c59ff1d664ef99c4454da865859284b33165bc7037f830ac61e5db0263a4387c441e92b0b3c9dd38014873d56d665bbba00c11c623634cbb17338822213b5463ec9b15ec5e2f3660d5aeac334e54760bb158ae41d9ce2e5b3d9d6c368b52247b56ced2bbda18ed9649715e1f28d013d277c9f8d55e647544e03a5d'),
    messages: COMMITTED_MESSAGES.concat(MESSAGES),
    disclosed_indexes: [1, 3, 5]
  }
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
  output: {
    proof: h2b('8de2b23c71d0cd0a2b1088ac05eca3956789465b81288f6a3d0597c9ca60b9d029f9e0871d8caa23e781752dcaa05a7f8c4b2766be6b4013b8498242faa4837f7a1a34f3642d8bb8424a5061421086846a247eeca1c00c623637f1af27f7cba98b282bdf73f94a2e53cd43d1376756a20a97fb727425bf897ba06d71c9ce347a5b581bd280ed5b9b7940a4bd995722c6685489e5eda2ef3961bc2cf6644f4258de9eba437b25a6341255d781c0dbcf3a24fac5113dcc696b1ea6b3c2a426d1d590312e41656919c66f5d7cfd98ce51106ddff816070342682ac54f3cdeacadf240c0f206fa34cc7f7ffa6247b62bf50e10a7ac678058fd00edb68cd7140d07f336cf10ef0cea7ba6518dc909873edb376e4fe0e9f45945c965096c33a7e5d83584554053fa3182aa24ae6206eb6f29052a3e49d3c26c89a61ef596a133fd9656ec0de0e6f01cdba4cc97ca75ccb1453714de703017cc020493b5b136effd04fd67050b06cb02efe6440a86d041ab59b46480c960ec0fade14a07dcebc84a1364aa50bc8060417cb5217485284b25e19b3026fdf907c9d58a986a3495f22773acbb1d02d0ce686acd47191c220dff271424077a3dc963abf2cec87a2fd380283df0167083493f1e9403c3d063fda6f6e12ddae5d61a7869a2ad0b334cc1d6de7725f027218b8b4cea653dbf11ad253cce670067192d32dba2a09f17149806b8fadc523a20d3004f3065bccc2291fd5c01147168ea88816c7d808358048937b160cdf6c83e837acf1955bb4c313c58eb393ce52e26c5a2c06f3daf40140906f47fc8bb964b45273b359ee0428c3eaa85c46c2a2a3c48c1955ed949a2774c7b4b95ddff6fc70ed20bed5cf86a9bdc4ff7712f5cef5d276dc0198ce4f46e2cc5aec156916e09d1f9f7994f34e8a3b018dc6b685d2925fee720c82d890bcf02626230e04fd15e54e019992173f1bc22c8832952dffa7f1fbfa1efd370e6b69d822ac4dc12737392079d9dea2a3d7dc954a0c926223423620be62f2bac962160ce01cec47321f3f92d1edd0a09356b6420ba8f2ade300ccd65d135eb140e629d65ec2116260c76eec6bf46af46c07768e50ea9'),
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
      // should only be 10 since there are no committed messages?
      count: 11
    }
  },
  output: {
    proof: h2b('a46cea8d9d0f919fdc86ca3dd1ac8b2a3e2378e284ba821202cd8de28d07cf961025b3e40ea6c04a8b40ce24254638c283966b37e6d484324d664fd4b7a0902e6183f0785933d6a169a9a2317d36f5e46eaceb1ea1aa8217a8814e17109880758e42a7ec9ce182a1cdfcc25f77e5731ef62538316488e74783bbd4b2fb9670da9d65b56385bb5386795529447e0263f331fc893fd155f22d61152e20d3b61ff16b31db1e9061022f6571a677cb0bccb56d0bb7df15cbc1bfdcb096035766d120fdeff44b253cf5eca13727e1e022b0a37120ab12381a0870d890d682dea4a4dba263cb80f19cb993febcf53865709548728d35b5e7ee27e55ee188d6e8d17a3c846f9e1c56ed42e9af450d73e7ef3826411062fd0fd2496acd5961ed94136691d8782f534201c741bc4d56317825222013638dce35ab399da8f2f5bc0a40e43a79348483d7d1b92b95277687ea25a53f17c3fca6cb30ac6d0e711c89c36f2a6034d6a2a12124e6743c88da53fa46483c37672c7161cf6273bd0fd2c1226f5b96a8e5572b4b7974edd4182a96708a01a05eeae79b84cf79bed7b01c22a32a2ad38fe92cb8eca55cec5d75f9ee876a2c0f2982f0a47bbfabd68627892687bb87a5f7bbcb2819d4439f93439e2aa1191a5643ed031197c66bcc1beb5d9dc1fb24f5f452c3f97900bd42194f198c62b8caa54173dd5a76260ae41c4aca2cca8430874e575cbba47d718300f0ef7bc4676553508938f9e4cab05889a7948f364a91c351f3796f5bfa8bc36cd46d040823c33164fb33187ebcf86f20af8ba7d75cf558c302e977d86d4485492f14c06198ee784a9510fe499cf516bd1c96e0ad60a5ad07fd5bdcdcb97a1bcec2ab951a56eff6'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6, 8]
  }
}];
/* eslint-enable max-len */
