'use strict';

const builtInDetectors = require('./detectors');

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

/**
 * Returns the first match of `value` against a list of regex patterns.
 */
function firstMatch(value, patterns) {
  for (const pattern of patterns) {
    // Clone without the global flag to avoid shared lastIndex state.
    const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
    const m = re.exec(value);
    if (m) {
      return m[0];
    }
  }
  return null;
}

/**
 * Normalizes a custom validator into the internal detector shape.
 *
 * Accepted forms:
 *   addValidator('name', /regex/)
 *   addValidator('name', { pattern: /regex/, severity, message, type })
 *   addValidator('name', { patterns: [/a/, /b/], ... })
 *   addValidator('name', { test: (value) => boolean | string, ... })
 */
function normalizeValidator(name, spec) {
  if (spec instanceof RegExp) {
    spec = { pattern: spec };
  }
  if (typeof spec === 'function') {
    spec = { test: spec };
  }
  if (!spec || typeof spec !== 'object') {
    throw new TypeError(
      `addValidator("${name}"): expected a RegExp, a function, or a config object.`
    );
  }

  const patterns = spec.patterns || (spec.pattern ? [spec.pattern] : []);
  const hasTest = typeof spec.test === 'function';

  if (patterns.length === 0 && !hasTest) {
    throw new TypeError(
      `addValidator("${name}"): must include "pattern", "patterns", or "test".`
    );
  }

  const severity = spec.severity || 'medium';
  if (!SEVERITY_RANK[severity]) {
    throw new TypeError(
      `addValidator("${name}"): invalid severity "${severity}" (use low|medium|high).`
    );
  }

  let message = spec.message || { en: `Pattern "${name}" matched.`, es: `Patrón "${name}" detectado.` };
  if (typeof message === 'string') {
    message = { en: message, es: message };
  }

  return {
    type: spec.type || name,
    name,
    severity,
    message,
    patterns,
    test: hasTest ? spec.test : null,
    custom: true
  };
}

class Scanner {
  /**
   * @param {object} [options]
   * @param {'en'|'es'} [options.lang='en']   Message language.
   * @param {string[]}  [options.categories]  Limit built-in detectors to these types.
   * @param {'low'|'medium'|'high'} [options.minSeverity='low'] Minimum reported severity.
   */
  constructor(options = {}) {
    this.lang = options.lang === 'es' ? 'es' : 'en';
    this.minSeverity = options.minSeverity || 'low';
    this.customValidators = new Map();

    const categories = options.categories;
    this.detectors = Array.isArray(categories)
      ? builtInDetectors.filter((d) => categories.includes(d.type))
      : builtInDetectors;
  }

  /**
   * Register a custom sub-function / validator.
   * @returns {Scanner} this (chainable)
   */
  addValidator(name, spec) {
    if (typeof name !== 'string' || !name.trim()) {
      throw new TypeError('addValidator: name must be a non-empty string.');
    }
    this.customValidators.set(name, normalizeValidator(name, spec));
    return this;
  }

  /** Remove a custom validator. */
  removeValidator(name) {
    return this.customValidators.delete(name);
  }

  /** List custom validator names. */
  listValidators() {
    return [...this.customValidators.keys()];
  }

  _runDetector(detector, value) {
    let match = null;

    if (detector.patterns && detector.patterns.length) {
      match = firstMatch(value, detector.patterns);
    }
    if (!match && typeof detector.test === 'function') {
      const result = detector.test(value);
      if (result) {
        match = typeof result === 'string' ? result : value;
      }
    }
    if (!match) {
      return null;
    }

    return {
      type: detector.type,
      severity: detector.severity,
      message: detector.message[this.lang] || detector.message.en,
      match
    };
  }

  /**
   * Scan a value and return the details of any threats found.
   * @returns {{ safe: boolean, value: any, threats: Array }}
   */
  scan(value) {
    // Non-string values (numbers, booleans, null, undefined) cannot inject.
    if (typeof value !== 'string') {
      return { safe: true, value, threats: [] };
    }

    const minRank = SEVERITY_RANK[this.minSeverity] || 1;
    const threats = [];
    const allDetectors = [...this.detectors, ...this.customValidators.values()];

    for (const detector of allDetectors) {
      if (SEVERITY_RANK[detector.severity] < minRank) {
        continue;
      }
      const threat = this._runDetector(detector, value);
      if (threat) {
        threats.push(threat);
      }
    }

    // Sorted by severity, highest first.
    threats.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    return { safe: threats.length === 0, value, threats };
  }

  /** true if the value is safe. */
  isSafe(value) {
    return this.scan(value).safe;
  }

  /**
   * Backward compatible: true if ANY threat is detected.
   * (Originally SQL only; now covers every category + custom validators.)
   */
  hasSql(value) {
    return !this.isSafe(value);
  }
}

module.exports = { Scanner, normalizeValidator };
