# Changelog

Todos los cambios notables de este proyecto se documentan aquí.
All notable changes to this project are documented here.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto usa [Versionado Semántico](https://semver.org/lang/es/).

## [1.0.0] - 2026-07-24

Reescritura completa de la librería / Full library rewrite.

### Added
- Escáner multi-amenaza: `sql-injection`, `xss`, `command-injection`,
  `path-traversal`, `nosql-injection`, `ldap-injection`, `template-injection`
  (SSTI) y `crlf-injection`.
- `scan(value)` devuelve el detalle `{ safe, value, threats[] }` con `type`,
  `severity` y `match` por amenaza.
- `isSafe(value)` como inverso de `hasSql`.
- Sub-funciones / validadores personalizados: `addValidator`, `removeValidator`,
  `listValidators` (aceptan RegExp, `{ pattern, patterns, severity, message }`
  o una función `test`).
- `createScanner(options)` con instancias aisladas y opciones `lang` (`es`/`en`),
  `categories` y `minSeverity`.
- Mensajes bilingües español / inglés.
- Suite de pruebas con `node --test` (`npm test`).
- Archivos `LICENSE`, `CHANGELOG.md` y campos de empaquetado (`files`, `engines`).

### Changed
- La detección ahora busca **sintaxis de ataque** en lugar de palabras sueltas,
  reduciendo drásticamente los falsos positivos (p. ej. `"hace join de datos"`
  ya no se marca como peligroso).
- `hasSql(value)` ahora cubre todas las categorías, no solo SQL.

### Fixed
- Variable global `re` sin declarar (fuga al scope global).
- `null` / `undefined` ya no se reportan como amenaza (antes devolvían `true`).

## [0.0.15] - anterior / previous

- Versión inicial con una única función `hasSql` basada en un regex de
  palabras clave SQL.

[1.0.0]: https://github.com/AndreyMartinez/sql-injection/releases/tag/v1.0.0
