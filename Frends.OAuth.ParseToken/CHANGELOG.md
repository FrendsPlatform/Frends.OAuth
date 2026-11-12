# Changelog

## [2.0.0] - 2026-11-12
### Changed
- ask results now use `Result` with success and error details.
- Added options `ThrowErrorOnFailure` and `ErrorMessageOnFailure`  to return failures instead of throwing and to provide a custom error message.
- **[Breaking Change]** Task now rethrows original exceptions or returns them in `Result` depends on new `Options` parameters

## [1.4.0] - 2026-11-02
### Added
- Options.ClockSkewSeconds for configuring clock skew tolerance in lifetime validation (default 300 seconds, same as before).

## [1.3.0] - 2025-12-02
### Added
- Support for handling array-type claims in the token, such as `"roles": ["editor", "admin"]`.

## [1.2.0] - 2024-08-21
### Added
- Support for new IdentityModel-versions.

## [1.1.0] - 2023-12-08
### Added
- New dictionary parameter 'ParseResult.Claims' that contains all claims in the token.

## [1.0.1] - 2022-08-04
### Changed
- Using custom result values instead of MS library classes for Frends integrity.

## [1.0.0] - 2022-07-01
### Added
- Initial implementation
