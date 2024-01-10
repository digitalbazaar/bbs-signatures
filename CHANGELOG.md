# @digitalbazaar/bbs-signatures ChangeLog

## 1.1.0 - 2024-01-dd

### Added
- Add `safeSecretKeyScalarBytes` to allow serialized `SK`
  values to be passed to `sign()` instead of `secretKey`
  to allow callers to use safely generated `SK` values
  directly instead of passing raw key material as `secretKey`
  and allowing the API to generate `SK` from that using `KeyGen`.

## 1.0.0 - 2024-01-10

### Added
- Initial version.
