'use strict';

const test = require('node:test');
const assert = require('node:assert');

const sqlInjection = require('../sql-injections');
const { createScanner } = sqlInjection;

test('compat: hasSql detecta SELECT ... FROM', () => {
  assert.strictEqual(sqlInjection.hasSql('SELECT * FROM users'), true);
});

test('compat: hasSql permite texto normal', () => {
  assert.strictEqual(sqlInjection.hasSql('Tu nombre'), false);
  assert.strictEqual(sqlInjection.hasSql('Trabajo donde quiero'), false);
});

test('null/undefined y no-strings son seguros', () => {
  assert.strictEqual(sqlInjection.hasSql(null), false);
  assert.strictEqual(sqlInjection.hasSql(undefined), false);
  assert.strictEqual(sqlInjection.hasSql(42), false);
  assert.strictEqual(sqlInjection.hasSql(true), false);
});

test('SQL: tautología clásica', () => {
  const r = sqlInjection.scan("' OR 1=1 --");
  assert.strictEqual(r.safe, false);
  assert.ok(r.threats.some((t) => t.type === 'sql-injection'));
});

test('SQL: UNION SELECT', () => {
  assert.strictEqual(sqlInjection.hasSql('1 UNION ALL SELECT username, password FROM users'), true);
});

test('XSS: <script>', () => {
  const r = sqlInjection.scan('<script>alert(1)</script>');
  assert.ok(r.threats.some((t) => t.type === 'xss'));
});

test('XSS: onerror handler', () => {
  assert.strictEqual(sqlInjection.hasSql('<img src=x onerror=alert(1)>'), true);
});

test('command injection: ; rm', () => {
  assert.strictEqual(sqlInjection.hasSql('foo.txt; rm -rf /'), true);
});

test('path traversal: ../', () => {
  assert.strictEqual(sqlInjection.hasSql('../../etc/passwd'), true);
});

test('NoSQL: operador $gt', () => {
  assert.strictEqual(sqlInjection.hasSql('{ "age": { "$gt": "" } }'), true);
});

test('SSTI: {{ 7*7 }}', () => {
  assert.strictEqual(sqlInjection.hasSql('{{7*7}}'), true);
});

test('scan devuelve estructura completa', () => {
  const r = sqlInjection.scan("admin' --");
  assert.strictEqual(typeof r.safe, 'boolean');
  assert.ok(Array.isArray(r.threats));
  const t = r.threats[0];
  assert.ok(t.type && t.severity && t.message && t.match);
});

test('idioma: mensajes en inglés', () => {
  const scanner = createScanner({ lang: 'en' });
  const r = scanner.scan('<script>x</script>');
  assert.match(r.threats[0].message, /injection|XSS/i);
});

test('sub-función: validador con RegExp', () => {
  const scanner = createScanner();
  scanner.addValidator('sin-arroba', /@/);
  const r = scanner.scan('hola@dominio.com');
  assert.strictEqual(r.safe, false);
  assert.ok(r.threats.some((t) => t.type === 'sin-arroba'));
});

test('sub-función: validador con función test', () => {
  const scanner = createScanner();
  scanner.addValidator('muy-largo', {
    test: (v) => (v.length > 10 ? v.slice(0, 10) + '…' : false),
    severity: 'low',
    message: 'Entrada demasiado larga'
  });
  assert.strictEqual(scanner.isSafe('corto'), true);
  assert.strictEqual(scanner.isSafe('esto es una entrada bastante larga'), false);
});

test('sub-función: removeValidator y listValidators', () => {
  const scanner = createScanner();
  scanner.addValidator('temp', /x/);
  assert.deepStrictEqual(scanner.listValidators(), ['temp']);
  assert.strictEqual(scanner.removeValidator('temp'), true);
  assert.deepStrictEqual(scanner.listValidators(), []);
});

test('addValidator es encadenable', () => {
  const scanner = createScanner()
    .addValidator('a', /a/)
    .addValidator('b', /b/);
  assert.strictEqual(scanner.listValidators().length, 2);
});

test('addValidator rechaza configuración inválida', () => {
  const scanner = createScanner();
  assert.throws(() => scanner.addValidator('x', {}), /pattern|patterns|test/);
  assert.throws(() => scanner.addValidator('', /x/), /name/);
  assert.throws(() => scanner.addValidator('y', { pattern: /a/, severity: 'critico' }), /severity/);
});

test('categories: limita los detectores integrados', () => {
  const scanner = createScanner({ categories: ['sql-injection'] });
  assert.strictEqual(scanner.hasSql('<script>x</script>'), false); // XSS ignorado
  assert.strictEqual(scanner.hasSql('SELECT * FROM t'), true);
});

test('minSeverity: filtra por umbral', () => {
  const scanner = createScanner({ minSeverity: 'high' });
  // path-traversal es 'medium' => se ignora con umbral 'high'
  assert.strictEqual(scanner.hasSql('../../secret'), false);
  assert.strictEqual(scanner.hasSql("' OR 1=1 --"), true); // high sí
});
