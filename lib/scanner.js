'use strict';

const builtInDetectors = require('./detectors');

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

/**
 * Extrae la primera coincidencia de un valor contra una lista de patrones.
 * Returns the first match of `value` against a list of regex patterns.
 */
function firstMatch(value, patterns) {
  for (const pattern of patterns) {
    // Clonamos sin flag global para evitar estado lastIndex compartido.
    const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
    const m = re.exec(value);
    if (m) {
      return m[0];
    }
  }
  return null;
}

/**
 * Normaliza un validador personalizado a la forma interna de detector.
 * Normalizes a custom validator into the internal detector shape.
 *
 * Formas aceptadas / accepted forms:
 *   addValidator('nombre', /regex/)
 *   addValidator('nombre', { pattern: /regex/, severity, message, type })
 *   addValidator('nombre', { patterns: [/a/, /b/], ... })
 *   addValidator('nombre', { test: (value) => boolean | string, ... })
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
      `addValidator("${name}"): se esperaba RegExp, función u objeto de configuración.`
    );
  }

  const patterns = spec.patterns || (spec.pattern ? [spec.pattern] : []);
  const hasTest = typeof spec.test === 'function';

  if (patterns.length === 0 && !hasTest) {
    throw new TypeError(
      `addValidator("${name}"): debe incluir "pattern", "patterns" o "test".`
    );
  }

  const severity = spec.severity || 'medium';
  if (!SEVERITY_RANK[severity]) {
    throw new TypeError(
      `addValidator("${name}"): severity inválida "${severity}" (usa low|medium|high).`
    );
  }

  let message = spec.message || { es: `Patrón "${name}" detectado.`, en: `Pattern "${name}" matched.` };
  if (typeof message === 'string') {
    message = { es: message, en: message };
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
   * @param {'es'|'en'} [options.lang='es']   Idioma de los mensajes.
   * @param {string[]}  [options.categories]  Limita los detectores integrados a estos tipos.
   * @param {'low'|'medium'|'high'} [options.minSeverity='low'] Umbral mínimo reportado.
   */
  constructor(options = {}) {
    this.lang = options.lang === 'en' ? 'en' : 'es';
    this.minSeverity = options.minSeverity || 'low';
    this.customValidators = new Map();

    const categories = options.categories;
    this.detectors = Array.isArray(categories)
      ? builtInDetectors.filter((d) => categories.includes(d.type))
      : builtInDetectors;
  }

  /**
   * Registra una sub-función / validador personalizado.
   * Register a custom sub-function / validator.
   * @returns {Scanner} this (encadenable / chainable)
   */
  addValidator(name, spec) {
    if (typeof name !== 'string' || !name.trim()) {
      throw new TypeError('addValidator: el nombre debe ser un string no vacío.');
    }
    this.customValidators.set(name, normalizeValidator(name, spec));
    return this;
  }

  /** Elimina un validador personalizado. / Remove a custom validator. */
  removeValidator(name) {
    return this.customValidators.delete(name);
  }

  /** Lista los nombres de los validadores personalizados. / List custom validator names. */
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
      message: detector.message[this.lang] || detector.message.es,
      match
    };
  }

  /**
   * Analiza un valor y devuelve el detalle de las amenazas encontradas.
   * Scan a value and return the details of any threats found.
   * @returns {{ safe: boolean, value: any, threats: Array }}
   */
  scan(value) {
    // Valores no textuales (números, booleanos, null, undefined) no inyectan.
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

    // Ordenadas por severidad, mayor primero. / Sorted by severity, highest first.
    threats.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    return { safe: threats.length === 0, value, threats };
  }

  /** true si el valor es seguro. / true if the value is safe. */
  isSafe(value) {
    return this.scan(value).safe;
  }

  /**
   * Compatibilidad histórica: true si se detecta CUALQUIER amenaza.
   * Backward compatible: true if ANY threat is detected.
   * (Antes solo SQL; ahora cubre todas las categorías + validadores propios.)
   */
  hasSql(value) {
    return !this.isSafe(value);
  }
}

module.exports = { Scanner, normalizeValidator };
