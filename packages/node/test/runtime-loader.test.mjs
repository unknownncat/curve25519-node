import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

function runNode(args, code) {
  return spawnSync(process.execPath, [...args, code], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

test("CJS eval can use axlsign + wasm + napi namespaces", () => {
  const code =
    "const m=require('./dist/cjs/index.js');" +
    "const seed=new Uint8Array(32);seed[0]=7;" +
    "const msg=new Uint8Array([1,2,3,4]);" +
    "const ax=m.axlsign.generateKeyPair(seed);" +
    "const sig=m.axlsign.sign(ax.private,msg);" +
    "if(!m.axlsign.verify(ax.public,msg,sig))throw new Error('axlsign verify failed');" +
    "const wk=m.wasm.x25519.generateKeyPair(seed);" +
    "const shared=m.wasm.x25519.sharedKey(wk.private,wk.public);" +
    "if(shared.length!==32)throw new Error('wasm shared key size');" +
    "if(!m.napi.isAvailable())throw new Error('napi unavailable');" +
    "const nk=m.napi.x25519.generateKeyPair(seed);" +
    "if(nk.public.length!==32)throw new Error('napi key size');";

  const result = runNode(["-e"], code);
  assert.equal(
    result.status,
    0,
    `CJS eval runtime failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
});

test("ESM eval can use axlsign + wasm + napi namespaces", () => {
  const code =
    "import('./dist/index.js').then((m)=>{" +
    "const seed=new Uint8Array(32);seed[0]=9;" +
    "const msg=new Uint8Array([5,6,7]);" +
    "const ax=m.axlsign.generateKeyPair(seed);" +
    "const sig=m.axlsign.sign(ax.private,msg);" +
    "if(!m.axlsign.verify(ax.public,msg,sig))throw new Error('axlsign verify failed');" +
    "const wk=m.wasm.x25519.generateKeyPair(seed);" +
    "const shared=m.wasm.x25519.sharedKey(wk.private,wk.public);" +
    "if(shared.length!==32)throw new Error('wasm shared key size');" +
    "if(!m.napi.isAvailable())throw new Error('napi unavailable');" +
    "const nk=m.napi.x25519.generateKeyPair(seed);" +
    "if(nk.public.length!==32)throw new Error('napi key size');" +
    "}).catch((err)=>{console.error(err);process.exit(1);});";

  const result = runNode(["--input-type=module", "-e"], code);
  assert.equal(
    result.status,
    0,
    `ESM eval runtime failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
});
