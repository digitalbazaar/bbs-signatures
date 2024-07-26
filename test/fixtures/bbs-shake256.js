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
  name: 'Message Generators',
  operation: 'create_generators',
  parameters: {
    count: MESSAGES.length + 1,
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'H2G_HM2S_'),
    // must compress points to match test vectors
    compress: true
  },
  output: BLS12381_SHAKE256.generators
}, {
  name: 'Message Scalars',
  operation: 'messages_to_scalars',
  parameters: {
    messages: MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'H2G_HM2S_')
  },
  output: BLS12381_SHAKE256.message_scalars
}, {
  name: 'Random Scalars',
  operation: 'mocked_calculate_random_scalars',
  parameters: {
    count: BLS12381_SHAKE256.random_scalars.length,
    ...BLS12381_SHAKE256.mocked_random_scalars_options
  },
  output: BLS12381_SHAKE256.random_scalars
}, {
  name: 'Valid Single Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]]
  },
  // signature
  output: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
  debug: {
    B: h2b('8bbc8c123d3f128f206dd0d2dae490e82af08b84e8d70af3dc291d32a6e98f635beefcc4533b2599804a164aabe68d7c'),
    domain: h2b('2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9')
  }
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES
  },
  // signature
  output: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
  debug: {
    B: h2b('ae8d4ebe248b9ad9c933d5661bfb46c56721fba2a1182ddda7e8fb443bda3c0a571ad018ad31d0b6d1f4e8b985e6c58d'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'No Header Valid Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b(''),
    messages: MESSAGES
  },
  // signature
  output: h2b('88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded'),
  debug: {
    B: h2b('8607ebc413b397c1e27ce591d1daa39f73da329018bda0f90bf996355cc28c3cdba19feeb81e35be9e1503a018e4086e'),
    domain: h2b('333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157'),
  }
}, {
  name: 'Valid Single Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]],
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded'),
    header: h2b(''),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'Modified Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c0798b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('91a10e73cf4090812e8ea25f31aaa61be53fcb42ce86e9f0e5df6f6dac4c3eee62ac846b0b83a5cfcbe78315175a4961'),
    T2: h2b('988f3d473186634e41478dc4527cf240e64de23a763037454d39a876862ebc617738ba6c458142e3746b01eab58ca8d7'),
    domain: h2b('2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c565241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec1433096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8bba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e069d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99f1764d8b890d121d65bfcc2984886ee0'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('8890adfc78da24768d59dbfdb3f380e2793e9018b20c23e9ba05baa60f1b21456bc047a5d27049dab5dc6a94696ce711'),
    T2: h2b('a49f953636d3651a3ae6fe45a99a2e4fec079eef3be8b8a6a4ba70885d7e028642f7224e9f451529915c88a7edc59fbe'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b2979e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4acec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2da9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241efb9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cbb0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be65865cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff13ea4c35cef7842b656e8ba4758e7558'),
  debug: {
    random_scalars: {
      r1: h2s('5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0'),
      r2: h2s('280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3'),
      e_tilde: h2s('39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230'),
      r1_tilde: h2s('61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089'),
      r3_tilde: h2s('63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089'),
      m_tilde_scalars: [
        h2s('020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b'),
        h2s('5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836'),
        h2s('049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28'),
        h2s('407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48'),
        h2s('1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c'),
        h2s('07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995')
      ]
    },
    T1: h2b('8b497dd4dcdcf7eb58c9b43e57e06bcea3468a223ae2fc015d7a86506a952d68055e73f5a5847e58f133ea154256d0da'),
    T2: h2b('8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('8ac336eea1d278656372d9914483c3d3b3069dfa4a7862293ac021dfeeebca93cadd7eb2b818f7b89719cdeffa5aa85989a7d691be11b1929a2bf089bfe9f2adc2c06788edc30585546efb74877f34ad91f0d6923b4ed7a53c49051dda8d056a95644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f2429372f3ad9d5946ffeb53f24d41ffcc83c32cbb68afc9b6e0b64eebd24c69c6a7bd3bca8a6394ed8ae315abd555a6996f34d9da7680447947b3f35f54c38b562e990ee4d17a21569af4fc02f2991e6db78cc32d3ef9f6069fc5c2d47c8d8ff116dfb8a59641641961b854427f67649df14ab6e63f2d0d2a0cba2b2e1e835d20cd45e41f274532e9d50f31a690e5fef1c1456b65c668b80d8ec17b09bd5fb3b2c4edd6d6f5f790a5d6da22eb9a1aa2196d1a607f3c753813ba2bc6ece15d35263218fc7667c5f0fabfffe74745a8000e0415c8dafd5654ce6850ac2c6485d02433fdaebd9993f8b86a2eebb3beb10b4cc7735330384a3f4dfd4d5b21998ad0227b37e736cf9c144a0386f28cccf27a01e50aab45dda8275eb877728e77d2055309dba8c6604e7cff0d2c46ce6026b8e232c192955f909da6e47c2130c7e3f4f'),
  debug: {
    challenge: h2s('4a70506add5b2eb0be9ff66e3ea8deae666f198edfbb1391c6834e6df4f1026d')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af33fda9e14ba4cc0fcad8015bce3fecc4704799bef9924ab19688fc04f760c4da35017072a3e295788eff1b0dc2311bb199c186f86ea0540379d5a2ac8b7bd02d22487f2acc0e299115e16097b970badea802752a6fcb56cfbbcc2569916a8d3fe6d2d0fb1ae801cfc5ce056699adf23e3cd16b1fdf197deac099ab093da049a5b4451d038c71b7cc69e8390967594f6777a855c7f5d301f0f0573211ac85e2e165ea196f78c33f54092645a51341b777f0f5342301991f3da276c04b0224f7308090ae0b290d428a0570a71605a27977e7daf01d42dfbdcec252686c3060a73d81f6e151e23e3df2473b322da389f15a55cb2cd8a2bf29ef0d83d4876117735465fae956d8df56ec9eb0e4748ad3ef5587797368c51a0ccd67eb6da38602a1c2d4fd411214efc6932334ba0bcbf562626e7c0e1ae0db912c28d99f194fa3cd3a2'),
  debug: {
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c565241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec1433096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8bba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e069d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99f1764d8b890d121d65bfcc2984886ee0'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b2979e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4acec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2da9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241efb9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cbb0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be65865cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff13ea4c35cef7842b656e8ba4758e7558'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('8ac336eea1d278656372d9914483c3d3b3069dfa4a7862293ac021dfeeebca93cadd7eb2b818f7b89719cdeffa5aa85989a7d691be11b1929a2bf089bfe9f2adc2c06788edc30585546efb74877f34ad91f0d6923b4ed7a53c49051dda8d056a95644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f2429372f3ad9d5946ffeb53f24d41ffcc83c32cbb68afc9b6e0b64eebd24c69c6a7bd3bca8a6394ed8ae315abd555a6996f34d9da7680447947b3f35f54c38b562e990ee4d17a21569af4fc02f2991e6db78cc32d3ef9f6069fc5c2d47c8d8ff116dfb8a59641641961b854427f67649df14ab6e63f2d0d2a0cba2b2e1e835d20cd45e41f274532e9d50f31a690e5fef1c1456b65c668b80d8ec17b09bd5fb3b2c4edd6d6f5f790a5d6da22eb9a1aa2196d1a607f3c753813ba2bc6ece15d35263218fc7667c5f0fabfffe74745a8000e0415c8dafd5654ce6850ac2c6485d02433fdaebd9993f8b86a2eebb3beb10b4cc7735330384a3f4dfd4d5b21998ad0227b37e736cf9c144a0386f28cccf27a01e50aab45dda8275eb877728e77d2055309dba8c6604e7cff0d2c46ce6026b8e232c192955f909da6e47c2130c7e3f4f'),
    signature: h2b('88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af33fda9e14ba4cc0fcad8015bce3fecc4704799bef9924ab19688fc04f760c4da35017072a3e295788eff1b0dc2311bb199c186f86ea0540379d5a2ac8b7bd02d22487f2acc0e299115e16097b970badea802752a6fcb56cfbbcc2569916a8d3fe6d2d0fb1ae801cfc5ce056699adf23e3cd16b1fdf197deac099ab093da049a5b4451d038c71b7cc69e8390967594f6777a855c7f5d301f0f0573211ac85e2e165ea196f78c33f54092645a51341b777f0f5342301991f3da276c04b0224f7308090ae0b290d428a0570a71605a27977e7daf01d42dfbdcec252686c3060a73d81f6e151e23e3df2473b322da389f15a55cb2cd8a2bf29ef0d83d4876117735465fae956d8df56ec9eb0e4748ad3ef5587797368c51a0ccd67eb6da38602a1c2d4fd411214efc6932334ba0bcbf562626e7c0e1ae0db912c28d99f194fa3cd3a2'),
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c565241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec1433096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8bba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e069d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99f1764d8b890d121d65bfcc2984886ee0'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c565241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec1433096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8bba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e069d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99f1764d8b890d121d65bfcc2984886ee0'),
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
    PK: h2b('b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c0798b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8'),
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d'),
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
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef'),
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
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
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
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
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
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded'),
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
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */
