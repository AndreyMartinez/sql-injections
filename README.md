SQL-INJECTIONS
==============

[![npm version](https://badge.fury.io/js/sql-injections.svg)](https://badge.fury.io/js/sql-injections)

Librería **sin dependencias** para detectar inyecciones y vulnerabilidades de
texto con una sola llamada, y **extensible** con tus propias sub-funciones.

Zero-dependency library to detect text-based injections / vulnerabilities with a
single call, **extensible** with your own sub-functions.

Detecta / Detects: **SQL injection, XSS, command injection, path traversal,
NoSQL, LDAP, SSTI (plantillas) y CRLF**.

---

Instalación / Install
---------------------

```
npm install sql-injections
```

Importar / Import
-----------------

```js
// Node (CommonJS)
const sqlInjection = require('sql-injections');

// ESM / React, Vue, Angular
import sqlInjection from 'sql-injections';
```

---

Uso básico / Basic use
----------------------

`hasSql(value)` devuelve `true` si detecta CUALQUIER amenaza, si no `false`.
Returns `true` if ANY threat is detected, otherwise `false`.

```js
sqlInjection.hasSql('SELECT * FROM users');  // true
sqlInjection.hasSql("' OR 1=1 --");          // true
sqlInjection.hasSql('<script>alert(1)</script>'); // true
sqlInjection.hasSql('Tu nombre');            // false
sqlInjection.hasSql(null);                   // false  (vacío = seguro)
```

Detalle de la amenaza / Threat detail
-------------------------------------

`scan(value)` devuelve la lista de amenazas encontradas.
Returns the list of threats found.

```js
sqlInjection.scan("' OR 1=1 --");
// {
//   safe: false,
//   value: "' OR 1=1 --",
//   threats: [
//     { type: 'sql-injection', severity: 'high',
//       message: 'Posible inyección SQL detectada.', match: "' OR 1=1" }
//   ]
// }

sqlInjection.isSafe('Tu nombre'); // true
```

---

Idioma / Language
-----------------

Elige `es` (por defecto) o `en` para los mensajes.
Choose `es` (default) or `en` for messages.

```js
const { createScanner } = sqlInjection;

const en = createScanner({ lang: 'en' });
en.scan('<script>x</script>').threats[0].message;
// "Possible XSS (malicious script/HTML) detected."
```

---

Sub-funciones / Custom validators
---------------------------------

Agrega tus propios patrones con `addValidator(nombre, spec)`.
Add your own patterns with `addValidator(name, spec)`.

```js
const scanner = sqlInjection.createScanner();

// 1) Con un RegExp / With a RegExp
scanner.addValidator('sin-emojis', /\p{Emoji}/u);

// 2) Con configuración / With config
scanner.addValidator('solo-alfanumerico', {
  pattern: /[^a-z0-9\s]/i,
  severity: 'medium',            // low | medium | high
  message: { es: 'Caracteres no permitidos.', en: 'Disallowed characters.' }
});

// 3) Con una función test (devuelve boolean o el texto que coincidió)
//    With a test function (returns boolean or the matched text)
scanner.addValidator('longitud-maxima', {
  test: (value) => value.length > 100 ? value.slice(0, 100) + '…' : false,
  severity: 'low',
  message: 'La entrada supera los 100 caracteres.'
});

scanner.scan('hola 🚀').safe;   // false  (regla sin-emojis)
scanner.listValidators();       // ['sin-emojis', 'solo-alfanumerico', 'longitud-maxima']
scanner.removeValidator('sin-emojis');
```

`addValidator` es encadenable / is chainable:

```js
scanner
  .addValidator('a', /a/)
  .addValidator('b', /b/);
```

---

Opciones del escáner / Scanner options
--------------------------------------

`createScanner(options)`:

| opción / option | valores / values            | descripción / description                              |
|-----------------|-----------------------------|--------------------------------------------------------|
| `lang`          | `'es'` \| `'en'`            | Idioma de los mensajes. / Message language.            |
| `categories`    | `string[]`                  | Limita los detectores integrados. / Limit built-ins.   |
| `minSeverity`   | `'low'`\|`'medium'`\|`'high'`| Umbral mínimo reportado. / Minimum reported severity.  |

```js
// Solo inyección SQL, ignora el resto / SQL only, ignore the rest
const soloSql = sqlInjection.createScanner({ categories: ['sql-injection'] });

// Solo amenazas de severidad alta / Only high-severity threats
const estricto = sqlInjection.createScanner({ minSeverity: 'high' });
```

Categorías disponibles / Available categories: `sql-injection`, `xss`,
`command-injection`, `path-traversal`, `nosql-injection`, `ldap-injection`,
`template-injection`, `crlf-injection`.

---

API
---

| Método / Method                 | Devuelve / Returns | Descripción / Description                          |
|---------------------------------|--------------------|---------------------------------------------------|
| `hasSql(value)`                 | `boolean`          | `true` si hay alguna amenaza. / any threat.       |
| `isSafe(value)`                 | `boolean`          | Inverso de `hasSql`. / Inverse of `hasSql`.       |
| `scan(value)`                   | `object`           | `{ safe, value, threats[] }`.                     |
| `addValidator(name, spec)`      | `Scanner`          | Registra una sub-función. / Register a validator. |
| `removeValidator(name)`         | `boolean`          | Elimina una sub-función. / Remove a validator.    |
| `listValidators()`              | `string[]`         | Nombres registrados. / Registered names.          |
| `createScanner(options)`        | `Scanner`          | Instancia aislada. / Isolated instance.           |

> **Nota / Note:** esta librería reduce falsos positivos buscando *sintaxis* de
> ataque, no palabras sueltas. Aun así, es una capa de detección: **no
> reemplaza** las consultas parametrizadas ni el escape/sanitización en el
> servidor. It's a detection layer, **not a replacement** for parameterized
> queries and proper server-side escaping.

---

Tests
-----

```
npm test
```

License
-------

MIT
