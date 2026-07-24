# Changelog

All notable changes to this project are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-24

Full library rewrite.

### Added
- Multi-threat scanner: `sql-injection`, `xss`, `command-injection`,
  `path-traversal`, `nosql-injection`, `ldap-injection`, `template-injection`
  (SSTI) and `crlf-injection`.
- `scan(value)` returns detail `{ safe, value, threats[] }` with `type`,
  `severity` and `match` per threat.
- `isSafe(value)` as the inverse of `hasSql`.
- Custom sub-functions / validators: `addValidator`, `removeValidator`,
  `listValidators` (accept a RegExp, `{ pattern, patterns, severity, message }`,
  or a `test` function).
- `createScanner(options)` with isolated instances and `lang` (`en`/`es`),
  `categories` and `minSeverity` options.
- Bilingual messages (English / Spanish), English by default.
- Test suite with `node --test` (`npm test`).
- `LICENSE`, `CHANGELOG.md` files and packaging fields (`files`, `engines`).

### Changed
- Detection now matches **attack syntax** instead of bare words, drastically
  reducing false positives (e.g. `"work where the teams join data"` is no longer
  flagged as dangerous).
- `hasSql(value)` now covers every category, not just SQL.

### Fixed
- Undeclared global variable `re` (leaked into the global scope).
- `null` / `undefined` are no longer reported as a threat (previously returned
  `true`).

## [0.0.15] - previous

- Initial version with a single `hasSql` function based on a SQL keyword regex.

[1.0.0]: https://github.com/AndreyMartinez/sql-injection/releases/tag/v1.0.0
