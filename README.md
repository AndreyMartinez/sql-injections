SQL-INJECTIONS
==============

[![npm version](https://badge.fury.io/js/sql-injections.svg)](https://badge.fury.io/js/sql-injections)

**Zero-dependency** library to detect text-based injections / vulnerabilities
with a single call, and **extensible** with your own custom sub-functions.

Detects: **SQL injection, XSS, command injection, path traversal, NoSQL, LDAP,
SSTI (templates) and CRLF**.

---

Install
-------

```
npm install sql-injections
```

Import
------

```js
// Node (CommonJS)
const sqlInjection = require('sql-injections');

// ESM / React, Vue, Angular
import sqlInjection from 'sql-injections';
```

---

Basic use
---------

`hasSql(value)` returns `true` if it detects ANY threat, otherwise `false`.

```js
sqlInjection.hasSql('SELECT * FROM users');       // true
sqlInjection.hasSql("' OR 1=1 --");               // true
sqlInjection.hasSql('<script>alert(1)</script>'); // true
sqlInjection.hasSql('Your name');                 // false
sqlInjection.hasSql(null);                         // false  (empty = safe)
```

Threat detail
-------------

`scan(value)` returns the list of threats found.

```js
sqlInjection.scan("' OR 1=1 --");
// {
//   safe: false,
//   value: "' OR 1=1 --",
//   threats: [
//     { type: 'sql-injection', severity: 'high',
//       message: 'Possible SQL injection detected.', match: "' OR 1=1" }
//   ]
// }

sqlInjection.isSafe('Your name'); // true
```

---

Language
--------

Messages default to English. Pass `lang: 'es'` for Spanish.

```js
const { createScanner } = sqlInjection;

const es = createScanner({ lang: 'es' });
es.scan('<script>x</script>').threats[0].message;
// "Posible XSS (script/HTML malicioso) detectado."
```

---

Custom validators (sub-functions)
---------------------------------

Add your own patterns with `addValidator(name, spec)`.

```js
const scanner = sqlInjection.createScanner();

// 1) With a RegExp
scanner.addValidator('no-emoji', /\p{Emoji}/u);

// 2) With config
scanner.addValidator('alphanumeric-only', {
  pattern: /[^a-z0-9\s]/i,
  severity: 'medium',            // low | medium | high
  message: 'Disallowed characters.'
});

// 3) With a test function (returns a boolean or the matched text)
scanner.addValidator('max-length', {
  test: (value) => value.length > 100 ? value.slice(0, 100) + '…' : false,
  severity: 'low',
  message: 'Input exceeds 100 characters.'
});

scanner.scan('hello 🚀').safe;   // false  (no-emoji rule)
scanner.listValidators();       // ['no-emoji', 'alphanumeric-only', 'max-length']
scanner.removeValidator('no-emoji');
```

`addValidator` is chainable:

```js
scanner
  .addValidator('a', /a/)
  .addValidator('b', /b/);
```

The `message` field also accepts an object for bilingual output:

```js
scanner.addValidator('no-emoji', {
  pattern: /\p{Emoji}/u,
  message: { en: 'Emojis are not allowed.', es: 'No se permiten emojis.' }
});
```

---

Scanner options
---------------

`createScanner(options)`:

| option        | values                        | description                          |
|---------------|-------------------------------|--------------------------------------|
| `lang`        | `'en'` \| `'es'`             | Message language (default `'en'`).   |
| `categories`  | `string[]`                    | Limit which built-in detectors run.  |
| `minSeverity` | `'low'`\|`'medium'`\|`'high'` | Minimum reported severity.           |

```js
// SQL injection only, ignore everything else
const sqlOnly = sqlInjection.createScanner({ categories: ['sql-injection'] });

// Only high-severity threats
const strict = sqlInjection.createScanner({ minSeverity: 'high' });
```

Available categories: `sql-injection`, `xss`, `command-injection`,
`path-traversal`, `nosql-injection`, `ldap-injection`, `template-injection`,
`crlf-injection`.

---

API
---

| Method                      | Returns   | Description                             |
|-----------------------------|-----------|----------------------------------------|
| `hasSql(value)`             | `boolean` | `true` if any threat is found.         |
| `isSafe(value)`             | `boolean` | Inverse of `hasSql`.                   |
| `scan(value)`               | `object`  | `{ safe, value, threats[] }`.          |
| `addValidator(name, spec)`  | `Scanner` | Register a custom sub-function.        |
| `removeValidator(name)`     | `boolean` | Remove a custom validator.             |
| `listValidators()`          | `string[]`| Registered validator names.            |
| `createScanner(options)`    | `Scanner` | Isolated instance.                     |

> **Note:** this library reduces false positives by matching attack *syntax*,
> not bare words. Even so, it is a detection layer — it is **not a replacement**
> for parameterized queries and proper server-side escaping/sanitization.

---

Tests
-----

```
npm test
```

License
-------

MIT
