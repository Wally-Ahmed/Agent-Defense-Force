// validate.js — a deliberately small JSON Schema checker.
//
// WHY THIS EXISTS INSTEAD OF ajv: this tree has zero npm dependencies by design,
// and the mesh's contracts are frozen — the set of keywords they can ever use is
// closed and known. So a focused validator that covers exactly those keywords is
// both auditable in one sitting and immune to a supply-chain surprise in a
// component whose whole job is to be the gate on untrusted model output.
//
// Supported keywords, chosen by reading contracts/mesh/*.schema.json and nothing
// else: type, required, enum, const, properties, additionalProperties(false),
// items, minLength, maxLength, minimum, maximum, minItems, minProperties,
// uniqueItems, pattern.
//
// UNSUPPORTED keywords are reported as an error rather than ignored. A validator
// that silently skips a constraint it does not understand is worse than no
// validator: it returns ok for input it never actually checked.

const SUPPORTED = new Set([
  "$schema",
  "$id",
  "title",
  "description",
  "x-contract",
  "type",
  "required",
  "enum",
  "const",
  "properties",
  "additionalProperties",
  "items",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "minItems",
  "minProperties",
  "uniqueItems",
  "pattern",
]);

/**
 * JSON Schema counts string length in Unicode CODE POINTS, not UTF-16 units.
 * The 400-char rationale cap is a contract number, so an emoji must not cost two
 * characters here while costing one to the contract's author.
 */
export function charLength(s) {
  return Array.from(String(s)).length;
}

/** Truncate to `max` code points. Used by parse.js for the rationale cap. */
export function clampChars(s, max) {
  const cps = Array.from(String(s));
  return cps.length <= max ? String(s) : cps.slice(0, max).join("");
}

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (Number.isInteger(v)) return "integer";
  if (typeof v === "number") return "number";
  return typeof v; // string | boolean | object | undefined | function
}

function typeMatches(want, v) {
  const actual = typeOf(v);
  if (want === "number") return actual === "number" || actual === "integer";
  if (want === "object") return actual === "object";
  return actual === want;
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (typeof a !== "object") return false;
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  return ak.every((k) => deepEqual(a[k], b[k]));
}

/**
 * @param {object} schema
 * @param {*} value
 * @returns {{ok:boolean, errors:{path:string,keyword:string,message:string}[]}}
 */
export function validate(schema, value) {
  const errors = [];
  check(schema, value, "$", errors);
  return { ok: errors.length === 0, errors };
}

/** Format errors as one line each — what the CLI and the run report print. */
export function formatErrors(errors) {
  return errors.map((e) => `${e.path}: ${e.message}`);
}

function fail(errors, path, keyword, message) {
  errors.push({ path, keyword, message });
}

function check(schema, value, path, errors) {
  if (schema === true || schema === undefined) return;
  if (schema === false) {
    fail(errors, path, "false", "schema forbids any value here");
    return;
  }

  for (const k of Object.keys(schema)) {
    if (!SUPPORTED.has(k)) {
      fail(errors, path, k, `unsupported schema keyword "${k}" — this validator cannot check it`);
    }
  }

  if (value === undefined) {
    // Presence is a `required` concern of the PARENT; an absent optional value
    // is vacuously valid.
    return;
  }

  // ---- type -------------------------------------------------------------
  if (schema.type !== undefined) {
    const wanted = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!wanted.some((t) => typeMatches(t, value))) {
      fail(
        errors,
        path,
        "type",
        `expected type ${wanted.join("|")}, got ${typeOf(value)}`,
      );
      return; // every other keyword assumes the type held
    }
    if (typeOf(value) === "number" && !Number.isFinite(value)) {
      fail(errors, path, "type", "number must be finite");
      return;
    }
  }

  // ---- const / enum -----------------------------------------------------
  if ("const" in schema && !deepEqual(value, schema.const)) {
    fail(errors, path, "const", `must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum !== undefined && !schema.enum.some((e) => deepEqual(e, value))) {
    fail(
      errors,
      path,
      "enum",
      `${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`,
    );
  }

  // ---- string -----------------------------------------------------------
  if (typeof value === "string") {
    if (schema.minLength !== undefined && charLength(value) < schema.minLength) {
      fail(errors, path, "minLength", `shorter than minLength ${schema.minLength}`);
    }
    if (schema.maxLength !== undefined && charLength(value) > schema.maxLength) {
      fail(
        errors,
        path,
        "maxLength",
        `${charLength(value)} characters exceeds maxLength ${schema.maxLength}`,
      );
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) {
      fail(errors, path, "pattern", `does not match /${schema.pattern}/`);
    }
  }

  // ---- number -----------------------------------------------------------
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      fail(errors, path, "minimum", `${value} is below minimum ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      fail(errors, path, "maximum", `${value} is above maximum ${schema.maximum}`);
    }
  }

  // ---- array ------------------------------------------------------------
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      fail(errors, path, "minItems", `needs at least ${schema.minItems} item(s)`);
    }
    if (schema.uniqueItems === true) {
      const seen = new Set();
      for (const item of value) {
        const key = JSON.stringify(item);
        if (seen.has(key)) {
          fail(errors, path, "uniqueItems", `duplicate item ${key}`);
          break;
        }
        seen.add(key);
      }
    }
    if (schema.items !== undefined) {
      value.forEach((item, i) => check(schema.items, item, `${path}[${i}]`, errors));
    }
  }

  // ---- object -----------------------------------------------------------
  if (typeOf(value) === "object") {
    const keys = Object.keys(value);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) {
      fail(
        errors,
        path,
        "minProperties",
        `needs at least ${schema.minProperties} propert(y|ies), has ${keys.length}`,
      );
    }
    for (const req of schema.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(value, req) || value[req] === undefined) {
        fail(errors, `${path}.${req}`, "required", `required property "${req}" is missing`);
      }
    }
    const props = schema.properties ?? {};
    for (const k of keys) {
      if (Object.prototype.hasOwnProperty.call(props, k)) {
        check(props[k], value[k], `${path}.${k}`, errors);
      } else if (schema.additionalProperties === false) {
        fail(
          errors,
          `${path}.${k}`,
          "additionalProperties",
          `unknown property "${k}" (additionalProperties is false)`,
        );
      } else if (typeof schema.additionalProperties === "object") {
        check(schema.additionalProperties, value[k], `${path}.${k}`, errors);
      }
    }
  }
}
