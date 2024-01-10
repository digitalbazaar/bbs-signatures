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

* [BBS Signatures RFC](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html)

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

const keyPair = await bbs.generateKeyPair();
// includes `secretKey` and `publicKey` keys, each is a `Uint8Array`
```

### Creating a BBS signature

Sign an optional `header` and an array of `messages` using BBS.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

const keyPair = await bbs.generateKeyPair();
// `header`
const header = new Uint8Array();
// N-many `messages`
const messages = [new Uint8Array()];
// `signature` is a `Uint8Array`
const signature = await bbs.sign({keyPair, header, messages});
```

### Verifying a BBS signature

Verify a full BBS signature. This verification method is less likely to be
used than `verifyProof()` as holders of signatures are expected to derive
proofs for verification by verifiers.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
const {publicKey} = keyPair;
// `verified` is a boolean
const verified = await bbs.verifySignature({
  publicKey, signature, header, messages
});
```

### Creating a BBS proof

Derive a proof from a BBS signature as a holder / prover.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
// as well as a custom `presentationHeader` and any `disclosedMessageIndexes`
const {publicKey} = keyPair;
// `proof`` is a boolean
const proof = await bbs.deriveProof({
  publicKey, signature, header, messages,
  presentationHeader, disclosedMessageIndexes
});
```

### Verifying a BBS proof

Verify a proof from a holder / prover.

```js
import * as bbs from '@digitalbazaar/bbs-signatures';

// pass `proof`, original signer's `publicKey` and`header`
// as well as holder's custom `presentationHeader`, `disclosedMessages`, and
// `disclosedMessageIndexes`
const {publicKey} = keyPair;
// `proof`` is a boolean
const verified = await bbs.verifyProof({
  publicKey, proof, header,
  presentationHeader, disclosedMessages, disclosedMessageIndexes
});
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
