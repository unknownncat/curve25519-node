import { timingSafeEqual } from "node:crypto";

export function bytesEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  const aa = Buffer.from(a.buffer, a.byteOffset, a.byteLength);
  const bb = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  return timingSafeEqual(aa, bb);
}

export function createIssueManager(config) {
  const warnings = [];

  function failOrWarn(message) {
    if (config.strict) {
      throw new Error(message);
    }
    warnings.push(message);
    if (config.debug) {
      console.warn(`[warn] ${message}`);
    }
  }

  function check(condition, message) {
    if (condition) return true;
    failOrWarn(message);
    return false;
  }

  return {
    warnings,
    check,
    failOrWarn,
  };
}

export function assertBytesEqual(label, actual, expected, issues) {
  return issues.check(bytesEqual(actual, expected), `${label}: bytes mismatch`);
}

export function assertTrue(label, condition, issues) {
  return issues.check(Boolean(condition), `${label}: expected true`);
}

export function assertNotNull(label, value, issues) {
  return issues.check(value !== null && value !== undefined, `${label}: expected non-null value`);
}

export function assertPayloadEqual(label, actual, expected, issues) {
  if (!assertNotNull(label, actual, issues)) return false;
  return assertBytesEqual(label, actual, expected, issues);
}
