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
  output: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
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
  output: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
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
  output: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
  debug: {
    B: h2b('8607ebc413b397c1e27ce591d1daa39f73da329018bda0f90bf996355cc28c3cdba19feeb81e35be9e1503a018e4086e'),
    domain: h2b('333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157'),
  }
}, {
  name: 'Valid Single Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]],
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
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
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c0798b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('aa74110474fcb00285be4fef3189da207720a7fbc84e3afae2c75b12d936f365c86c9ac5fa39119ef5e094d151bfef0f'),
    T2: h2b('988f3d473186634e41478dc4527cf240e64de23a763037454d39a876862ebc617738ba6c458142e3746b01eab58ca8d7'),
    domain: h2b('2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('8aae12173b9fc9032a603c9e61b0c3dfa9b8d0c4428d7acba4317aa90354ed3fff1afb720cd0e15a912eb2d7ece8037f'),
    T2: h2b('a49f953636d3651a3ae6fe45a99a2e4fec079eef3be8b8a6a4ba70885d7e028642f7224e9f451529915c88a7edc59fbe'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af36ac442df87545e0e8303260a97a0d251de15fc1447b82fff6b47ffb0ff94022869b315dc48c9302523b2715ddec9f56975a0892f5f3aeed3203c29c7a03cfc79187eef45f72b7c5bf0d4fc852adcc7528c05b0ba9554f2eb9b39c168a4dd6bdc3ac603ce14856184f6d713139f9d3930efcc9842e724517dbccff6912088b399447ff786e2f9db8b1061cc89a1636ba9282344729bcd19228ccde2318286c5a115baaf317b48341ac7906c6cc957f94b060351563907dca7f598a4cbdaeab26c4a4fcb6aa7ff6fd999c5f9bc0c9a9b0e4f4a3301de901a6c68b174ed24ccf5cd0cac6726766c91aded6947c4b446a9dfc8ec0aa11ec9ddda57dcc22c554a83a25471be93ae69ad9234b1fc3d133550d7ff570a4bc6555cd0bf23ee1b2a994b2434ea222bc221ba1615adc53b47ba99fc5a66495585d4c86f1f0aecb18df802b8'),
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
    T1: h2b('8bec86c26337655162b39f97e38ee5c0bbd2b6e8900d1d68fc4c27679dbe88dc76f313526bc800dd3209bef6b8907e95'),
    T2: h2b('8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('ada2a57ae3d869255d1533f74317b131ad4f0f24cae413ac40028d70f0cf0372b503ff6e705220532727002b8958ebf987e2e8378984afe3214511b9feeee830ffe3121ed005d2c382c04e6db37b646bc2f7002f3699648570fe9b67a0a5aac995644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f6b676faadceff172a0002325e7f22f47ed9b5125f30dd5fffe9ed1dc99dc283100cb702fa63aaef1bd1f530a5368ca4c7e78a01c7fcc3563b25c6c10c0e063092cbe2590fdfcc7b6a2859e482796f1f6783a41dfdf133ce28d13071b77cbe7fe06bf6e138bd3323e7edc4a6ec9942bfa0b6d1287836e2b1c2db84833d8325d145e6d2a3e94ddd5b6f58c1d1b2a15a854f7cf46711239ebe522bf5e428131e31e2f5f322eba2399fa7a8efec4be722dcaf6ec6adaf84af72c3d7690072d07928045327f3a6587102b066fb9cf96b27aca7f5698a2ec66d04efa05ed57fd6ac27636322c013a168100b733269e9bd6f23d7562affebafc3d9b3c5f54a0c57216b733f8ecb24dc292c17e18b6b8e0f3b8303dfaedee84fba02d491994b95f965deb3c1295545bb9802d98449d98d1af18e9c60536146cfa7aa267bd888b25552dd2'),
  debug: {
    challenge: h2s('1cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af37286b5d6012208605b7c3fe5457936db502aa7eec43ae4a9d1bdf5f675153d521b1e587c6ddd195e80358667aae42e64754595a0d35c1d6e72f147f67f591c823e75340360615b9c0173445afe53002d4face239979f697eff7183826449d4dc285a15e0c6afec9289b0b39e0741d0c4925c090f722569b8c64e2829904a02ec1ab6340cfe999a59196bbb8da2be2a89ddd84378dba0a22533e76fd6ac14f2b52a3972b041950539c19debaf7454e6ef3b9cec23086dc26b8a104e319aa4394e4e376c133d6c00133daf2f414e1df8ebca2de0a23e6ba37663f8074b9c8f440e37459bc08a8a4a587b78b2102c81b2f48f0fa73c331f7b6f64f6d8d50f3f8cb1424626f9cf3171cdea7f8cedb7bbb5a269856b37e8ba16ba8604fb1681be22dc6b64827a8326691524b7c05ac462ec8d8eee64bc6e09df622bb974fba93a75f8'),
  debug: {
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
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
    proof: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af36ac442df87545e0e8303260a97a0d251de15fc1447b82fff6b47ffb0ff94022869b315dc48c9302523b2715ddec9f56975a0892f5f3aeed3203c29c7a03cfc79187eef45f72b7c5bf0d4fc852adcc7528c05b0ba9554f2eb9b39c168a4dd6bdc3ac603ce14856184f6d713139f9d3930efcc9842e724517dbccff6912088b399447ff786e2f9db8b1061cc89a1636ba9282344729bcd19228ccde2318286c5a115baaf317b48341ac7906c6cc957f94b060351563907dca7f598a4cbdaeab26c4a4fcb6aa7ff6fd999c5f9bc0c9a9b0e4f4a3301de901a6c68b174ed24ccf5cd0cac6726766c91aded6947c4b446a9dfc8ec0aa11ec9ddda57dcc22c554a83a25471be93ae69ad9234b1fc3d133550d7ff570a4bc6555cd0bf23ee1b2a994b2434ea222bc221ba1615adc53b47ba99fc5a66495585d4c86f1f0aecb18df802b8'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
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
    proof: h2b('ada2a57ae3d869255d1533f74317b131ad4f0f24cae413ac40028d70f0cf0372b503ff6e705220532727002b8958ebf987e2e8378984afe3214511b9feeee830ffe3121ed005d2c382c04e6db37b646bc2f7002f3699648570fe9b67a0a5aac995644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f6b676faadceff172a0002325e7f22f47ed9b5125f30dd5fffe9ed1dc99dc283100cb702fa63aaef1bd1f530a5368ca4c7e78a01c7fcc3563b25c6c10c0e063092cbe2590fdfcc7b6a2859e482796f1f6783a41dfdf133ce28d13071b77cbe7fe06bf6e138bd3323e7edc4a6ec9942bfa0b6d1287836e2b1c2db84833d8325d145e6d2a3e94ddd5b6f58c1d1b2a15a854f7cf46711239ebe522bf5e428131e31e2f5f322eba2399fa7a8efec4be722dcaf6ec6adaf84af72c3d7690072d07928045327f3a6587102b066fb9cf96b27aca7f5698a2ec66d04efa05ed57fd6ac27636322c013a168100b733269e9bd6f23d7562affebafc3d9b3c5f54a0c57216b733f8ecb24dc292c17e18b6b8e0f3b8303dfaedee84fba02d491994b95f965deb3c1295545bb9802d98449d98d1af18e9c60536146cfa7aa267bd888b25552dd2'),
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
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
    proof: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af37286b5d6012208605b7c3fe5457936db502aa7eec43ae4a9d1bdf5f675153d521b1e587c6ddd195e80358667aae42e64754595a0d35c1d6e72f147f67f591c823e75340360615b9c0173445afe53002d4face239979f697eff7183826449d4dc285a15e0c6afec9289b0b39e0741d0c4925c090f722569b8c64e2829904a02ec1ab6340cfe999a59196bbb8da2be2a89ddd84378dba0a22533e76fd6ac14f2b52a3972b041950539c19debaf7454e6ef3b9cec23086dc26b8a104e319aa4394e4e376c133d6c00133daf2f414e1df8ebca2de0a23e6ba37663f8074b9c8f440e37459bc08a8a4a587b78b2102c81b2f48f0fa73c331f7b6f64f6d8d50f3f8cb1424626f9cf3171cdea7f8cedb7bbb5a269856b37e8ba16ba8604fb1681be22dc6b64827a8326691524b7c05ac462ec8d8eee64bc6e09df622bb974fba93a75f8'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
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
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
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
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
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
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
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
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
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
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
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
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
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
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
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
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */
