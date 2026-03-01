import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

test("CJS require loads package API from dist/cjs", () => {
  const cjs = require("../dist/cjs/index.js");

  assert.equal(typeof cjs, "object");
  assert.equal(typeof cjs.default, "object");
  assert.equal(typeof cjs.x25519, "object");
  assert.equal(typeof cjs.ed25519, "object");
  assert.equal(typeof cjs.axlsign, "object");
  assert.equal(typeof cjs.wasm, "object");

  assert.equal(typeof cjs.asBytes32, "function");
  assert.equal(typeof cjs.sharedKey, "function");
  assert.equal(typeof cjs.generateKeyPair, "function");
  assert.equal(typeof cjs.sign, "function");
  assert.equal(typeof cjs.verify, "function");
  assert.equal(typeof cjs.axlsign.sign, "function");
  assert.equal(typeof cjs.wasm.x25519.sharedKey, "function");
});
