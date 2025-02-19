# BBS Signatures _(@digitalbazaar/bbs-signatures)_

[![Node.js CI](https://github.com/digitalbazaar/bbs-signatures/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/bbs-signatures/actions?query=workflow%3A%22Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/bbs-signatures.svg)](https://npm.im/@digitalbazaar/bbs-signatures)

> A JavaScript BBS Signatures Implementation

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

See also (related specs):

* [BBS Signatures RFC](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-06.html)
* [BBS Blind Signatures RFC](https://www.ietf.org/archive/id/draft-kalos-bbs-blind-signatures-03.html)
* [BBS Pseudonyms RFC](https://www.ietf.org/archive/id/draft-kalos-bbs-per-verifier-linkability-00.html)

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 18+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/bbs-signatures.git
cd bbs-signatures
npm install
```

## Usage

### Generating a new public/secret key pair

To generate a new public/secret BLS12-381 key pair for use with BBS signatures:

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

const {secretKey, publicKey} = await bbs.generateKeyPair({
  ciphersuite: 'BLS12-381-SHA-256'
  // same as using the constant: bbs.CIPHERSUITES.BLS12381_SHA256
});
// includes `secretKey` and `publicKey` keys, each is a `Uint8Array`
// `secretKey` is big-endian-encoded scalar
// `publicKey` is compressed (x, y) coordinates of a BLS12-381 G2 point
// other ciphersuite choice is: 'BLS12-381-SHAKE-256'
```

### Creating a BBS signature

Sign an optional `header` and an array of `messages` using BBS.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

const {secretKey, publicKey} = await bbs.generateKeyPair({
  ciphersuite: 'BLS12-381-SHA-256'
});
// `header`
const header = new Uint8Array();
// N-many `messages`, each is a `Uint8Array`, use `TextEncoder` to
// express strings as UTF-8 bytes
const messages = [new TextEncoder().encode('some message')];
// `signature` is a `Uint8Array`
const signature = await bbs.sign({secretKey, publicKey, header, messages});
```

### Verifying a BBS signature

Verify a full BBS signature. This verification method is less likely to be
used than `verifyProof()` as holders of signatures are expected to derive
proofs for verification by verifiers.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
const verified = await bbs.verifySignature({
  publicKey, signature, header, messages,
  ciphersuite: 'BLS12-381-SHA-256'
});
// `verified` is a boolean
```

### Creating a BBS proof

Derive a proof from a BBS signature as a holder / prover.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
// as well as a custom `presentationHeader` and any `disclosedMessageIndexes`
const proof = await bbs.deriveProof({
  publicKey, signature, header, messages,
  presentationHeader, disclosedMessageIndexes,
  ciphersuite: 'BLS12-381-SHA-256'
});
// `proof` is a `Uint8Array` containing a BBS proof
```

### Verifying a BBS proof

Verify a proof from a holder / prover.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass `proof`, original signer's `publicKey` and`header`
// as well as holder's custom `presentationHeader`, `disclosedMessages`, and
// `disclosedMessageIndexes`
const verified = await bbs.verifyProof({
  publicKey, proof, header,
  presentationHeader, disclosedMessages, disclosedMessageIndexes,
  ciphersuite: 'BLS12-381-SHA-256'
});
// `verified` is a boolean
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © 2024 Digital Bazaar
