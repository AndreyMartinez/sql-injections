'use strict';

/**
 * Built-in detectors for injection / text-based vulnerability patterns.
 *
 * Each detector:
 *   type:      category id
 *   severity:  'low' | 'medium' | 'high'
 *   message:   { en, es } human-readable description
 *   patterns:  RegExp[] — attack *syntax*, NOT bare words
 *              (matching real syntax keeps false positives low)
 */

const detectors = [
  {
    type: 'sql-injection',
    severity: 'high',
    message: {
      en: 'Possible SQL injection detected.',
      es: 'Posible inyección SQL detectada.'
    },
    patterns: [
      // Tautologies: ' OR 1=1 , OR '1'='1'
      /(['"`]?\s*)\b(or|and)\b(\s*['"`]?\s*)\d+\s*=\s*\d+/i,
      /['"`]\s*\b(or|and)\b\s*['"`]?\s*['"`\d]/i,
      // UNION SELECT
      /\bunion\b\s+(all\s+)?\bselect\b/i,
      // SELECT ... FROM
      /\bselect\b[\s\S]{1,200}?\bfrom\b/i,
      // Stacked queries / dangerous DDL-DML: ; DROP, ; DELETE ...
      /(^|;)\s*\b(drop|truncate|alter|create|insert|update|delete)\b\s+(table|into|from|database)?/i,
      /\b(drop|truncate)\s+table\b/i,
      // SQL comments after a quote / closing token: '--  ';#  '/*
      /['"`)\s];?\s*(--|#|\/\*)/,
      // Time-based blind
      /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
      // Sensitive functions and objects
      /\b(load_file|into\s+outfile|information_schema|xp_cmdshell|sysobjects)\b/i
    ]
  },
  {
    type: 'xss',
    severity: 'high',
    message: {
      en: 'Possible XSS (malicious script/HTML) detected.',
      es: 'Posible XSS (script/HTML malicioso) detectado.'
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
      en: 'Possible OS command injection detected.',
      es: 'Posible inyección de comandos del sistema detectada.'
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
      en: 'Possible path traversal (unauthorized path access).',
      es: 'Posible path traversal (acceso a rutas no permitidas).'
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
      en: 'Possible NoSQL (MongoDB) injection detected.',
      es: 'Posible inyección NoSQL (MongoDB) detectada.'
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
      en: 'Possible LDAP injection detected.',
      es: 'Posible inyección LDAP detectada.'
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
      en: 'Possible Server-Side Template Injection (SSTI) detected.',
      es: 'Posible inyección de plantillas (SSTI) detectada.'
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
      en: 'Possible CRLF / HTTP header injection detected.',
      es: 'Posible inyección CRLF / de cabeceras HTTP detectada.'
    },
    patterns: [
      /(\r\n|\r|\n|%0d%0a|%0a|%0d)\s*(set-cookie|location|content-length|content-type)\s*:/i
    ]
  }
];

module.exports = detectors;
