# @digitalbazaar/bbs-signatures ChangeLog

## 3.0.0 - 2024-03-dd

### Changed
- **BREAKING**: Update challenge format to work with IETF BBS draf 6. This
  version is incompatible with previous versions and any proofs generated
  using the previous version should be considered obsolete and non-standard,
  i.e., they will not be verifiable via any interoperable software.

## 2.1.0 - 2024-01-11

### Added
- Add `secretKeyToPublicKey` helper utility to convert a `secretKey`
  to a `publicKey`.

## 2.0.0 - 2024-01-10

### Changed
- **BREAKING**: The `secretKey` returned from `generateKeyPair` and
  used in `sign()` is now the big-endian-encoded secret scalar value instead
  of the seed key material used to generate it. This change was made in
  the interest of interoperability. Once deserialized to a scalar value as
  `SK`, it is checked to ensure `0 < SK < r`.

## 1.2.0 - 2024-01-10

### Added
- Export ciphersuite string constants for external use.

## 1.1.0 - 2024-01-10

### Added
- Add `safeSecretKeyScalarBytes` to allow serialized `SK`
  values to be passed to `sign()` instead of `secretKey`
  to allow callers to use safely generated `SK` values
  directly instead of passing raw key material as `secretKey`
  and allowing the API to generate `SK` from that using `KeyGen`.

## 1.0.0 - 2024-01-10

### Added
- Initial version.
