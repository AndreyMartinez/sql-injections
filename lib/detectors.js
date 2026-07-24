'use strict';

/**
 * Detectores integrados de patrones de inyección / vulnerabilidades de texto.
 * Built-in detectors for injection / text-based vulnerability patterns.
 *
 * Cada detector / Each detector:
 *   type:        identificador de la categoría / category id
 *   severity:    'low' | 'medium' | 'high'
 *   message:     { es, en } descripción legible / human-readable description
 *   patterns:    RegExp[] — sintaxis de ataque, NO palabras sueltas
 *                (busca sintaxis real para reducir falsos positivos)
 *                attack syntax, NOT bare words (fewer false positives)
 */

const detectors = [
  {
    type: 'sql-injection',
    severity: 'high',
    message: {
      es: 'Posible inyección SQL detectada.',
      en: 'Possible SQL injection detected.'
    },
    patterns: [
      // Tautologías: ' OR 1=1 , OR '1'='1'
      /(['"`]?\s*)\b(or|and)\b(\s*['"`]?\s*)\d+\s*=\s*\d+/i,
      /['"`]\s*\b(or|and)\b\s*['"`]?\s*['"`\d]/i,
      // UNION SELECT
      /\bunion\b\s+(all\s+)?\bselect\b/i,
      // SELECT ... FROM
      /\bselect\b[\s\S]{1,200}?\bfrom\b/i,
      // Consultas apiladas / DDL-DML peligrosas: ; DROP, ; DELETE ...
      /(^|;)\s*\b(drop|truncate|alter|create|insert|update|delete)\b\s+(table|into|from|database)?/i,
      /\b(drop|truncate)\s+table\b/i,
      // Comentarios SQL tras comilla / cierre: '--  ';#  '/*
      /['"`)\s];?\s*(--|#|\/\*)/,
      // Basadas en tiempo / time-based blind
      /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
      // Funciones y objetos sensibles
      /\b(load_file|into\s+outfile|information_schema|xp_cmdshell|sysobjects)\b/i
    ]
  },
  {
    type: 'xss',
    severity: 'high',
    message: {
      es: 'Posible XSS (script/HTML malicioso) detectado.',
      en: 'Possible XSS (malicious script/HTML) detected.'
    },
    patterns: [
      /<\s*script[\s>]/i,
      /<\s*\/\s*script\s*>/i,
      /javascript\s*:/i,
      /\bon\w+\s*=\s*['"]?[^'">\s]/i, // onerror= onload= onclick=
      /<\s*(iframe|img|svg|body|object|embed|video|audio)[^>]*\b(on\w+|src)\s*=/i,
      /\b(document\.cookie|document\.write|window\.location|eval\s*\()/i,
      /data\s*:\s*text\/html/i
    ]
  },
  {
    type: 'command-injection',
    severity: 'high',
    message: {
      es: 'Posible inyección de comandos del sistema detectada.',
      en: 'Possible OS command injection detected.'
    },
    patterns: [
      /[;&|]\s*\b(ls|cat|rm|mv|cp|wget|curl|nc|bash|sh|zsh|powershell|whoami|id|uname|ping|chmod|chown|kill)\b/i,
      /\$\([^)]{1,200}\)/,          // $(command)
      /`[^`]{1,200}`/,              // `command`
      /\|\|\s*\S/,                  // || cmd
      /&&\s*\S/,                    // && cmd
      />\s*\/dev\/(tcp|null)/i
    ]
  },
  {
    type: 'path-traversal',
    severity: 'medium',
    message: {
      es: 'Posible path traversal (acceso a rutas no permitidas).',
      en: 'Possible path traversal (unauthorized path access).'
    },
    patterns: [
      /\.\.[\/\\]/,                 // ../ or ..\
      /%2e%2e(%2f|%5c)/i,           // encoded ../
      /\/etc\/(passwd|shadow|hosts)/i,
      /(^|[\s"'=])[a-z]:\\(windows|users|boot)/i,
      /\.\.%2f/i
    ]
  },
  {
    type: 'nosql-injection',
    severity: 'high',
    message: {
      es: 'Posible inyección NoSQL (MongoDB) detectada.',
      en: 'Possible NoSQL (MongoDB) injection detected.'
    },
    patterns: [
      /[$]\b(where|ne|gt|gte|lt|lte|in|nin|or|and|not|regex|exists|expr)\b/i,
      /\{\s*['"]?\s*[$]\w+/,        // { "$gt": ... }
      /\.\s*(find|findOne|aggregate)\s*\(\s*\{/i
    ]
  },
  {
    type: 'ldap-injection',
    severity: 'medium',
    message: {
      es: 'Posible inyección LDAP detectada.',
      en: 'Possible LDAP injection detected.'
    },
    patterns: [
      /\*\s*\)\s*\(/,               // *)(
      /\)\s*[|&]\s*\(/,             // )(|( or )(&(
      /\(\s*[|&]\s*\(/
    ]
  },
  {
    type: 'template-injection',
    severity: 'medium',
    message: {
      es: 'Posible inyección de plantillas (SSTI) detectada.',
      en: 'Possible Server-Side Template Injection (SSTI) detected.'
    },
    patterns: [
      /\{\{[\s\S]{1,200}?\}\}/,     // {{ 7*7 }}
      /\{%[\s\S]{1,200}?%\}/,       // {% ... %}
      /<%[\s\S]{1,200}?%>/,         // <% ... %>
      /[#$]\{[\s\S]{1,200}?\}/      // ${...} #{...}
    ]
  },
  {
    type: 'crlf-injection',
    severity: 'medium',
    message: {
      es: 'Posible inyección CRLF / de cabeceras HTTP detectada.',
      en: 'Possible CRLF / HTTP header injection detected.'
    },
    patterns: [
      /(\r\n|\r|\n|%0d%0a|%0a|%0d)\s*(set-cookie|location|content-length|content-type)\s*:/i
    ]
  }
];

module.exports = detectors;
