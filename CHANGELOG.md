# @digitalbazaar/bbs-signatures ChangeLog

## 3.2.0 - 2026-mm-dd

### Changed
- **NOTE**: Update the (not yet exported) pseudonym implementation to the
  current BBS per Verifier Linkability draft (cfrg/draft-irtf-cfrg-bbs-
  pseudonyms, commit `fcbba956`): `nym_secrets` is a vector of scalars
  (`prover_nyms` / `nym_secrets` parameters replace `prover_nym` /
  `nym_secret`); the signer's entropy is added to the last element; the
  vector's length is bound into the header (`length_nym_vector`); the
  pseudonym is computed from a polynomial in
  `hash_to_scalar(context_id, api_id || "VECT_NYM_SECRETS")`; the proof
  challenge includes the length-prefixed `context_id`.

### Added
- Tests that run the Blind BBS and pseudonym draft repositories' own
  fixtures, and `scripts/update-spec-fixtures.js` to refresh them.

### Removed
- Transcribed test vectors from the previous (single `nym_secret`)
  pseudonym draft, superseded by the draft repository's fixtures.

## 3.1.1 - 2026-mm-dd

### Fixed
- Fix `BLS12-381-SHAKE-256` `hash_to_curve_g1` with `@noble/curves` 2.3.0+
  (allowed by the `^2.2.0` range). Since 2.3.0, `hashToCurve()` only honors a
  per-call `DST` (as its `H2CDSTOpts` type always declared), so the suite's
  `expand: 'xof'`, `hash: shake256` and `k` options were silently ignored and
  SHA-256 XMD was used instead, breaking every SHAKE-256 signature and proof.
  `hash_to_curve` is now composed from `hash_to_field` (with
  `expand_message_xof`) and `mapToCurve()`; works with 2.2.0 and 2.4.0.

## 3.1.0 - 2026-06-01

### Changed
- Update `@noble/curves` and `@noble/hashes` libraries.

## 3.0.0 - 2024-08-19

### Changed
- **BREAKING**: Update challenge format to work with IETF BBS draft 6. This
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
