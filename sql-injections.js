'use strict';

/**
 * sql-injections
 * ------------------------------------------------------------------
 * Librería sin dependencias para detectar inyecciones y vulnerabilidades
 * de texto (SQL, XSS, comandos, path traversal, NoSQL, LDAP, plantillas,
 * CRLF) mediante una sola llamada, y extensible con sub-funciones propias.
 *
 * Zero-dependency library to detect text-based injections / vulnerabilities
 * with a single call, extensible with custom sub-functions.
 *
 * Uso rápido / Quick use:
 *   const sqlInjection = require('sql-injections');
 *   sqlInjection.hasSql("SELECT * FROM users");   // true
 *   sqlInjection.hasSql("Tu nombre");             // false
 *   sqlInjection.scan("' OR 1=1 --");             // { safe:false, threats:[...] }
 *   sqlInjection.addValidator('sin-emojis', { pattern: /\p{Emoji}/u });
 */

const { Scanner } = require('./lib/scanner');
const detectors = require('./lib/detectors');

// Instancia por defecto compartida. / Shared default instance.
const defaultScanner = new Scanner();

/**
 * Crea un escáner aislado con su propia configuración y validadores.
 * Create an isolated scanner with its own config and validators.
 * @param {object} [options] Ver Scanner. / See Scanner.
 * @returns {Scanner}
 */
function createScanner(options) {
  return new Scanner(options);
}

module.exports = defaultScanner;

// API extra sobre la instancia por defecto. / Extra API on the default instance.
module.exports.createScanner = createScanner;
module.exports.Scanner = Scanner;
module.exports.detectors = detectors;
