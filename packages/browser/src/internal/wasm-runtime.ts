import initAxlsign, * as axlsignBindings from "./axlsign-wasm/axlsign_wasm.js";
import initCurve25519, * as curveBindings from "./curve25519-wasm/curve25519_wasm.js";

type AxlsignInitInput = Parameters<typeof initAxlsign>[0];
type CurveInitInput = Parameters<typeof initCurve25519>[0];

export interface WasmInitOptions {
  axlsign?: AxlsignInitInput;
  curve25519?: CurveInitInput;
}

let initialized = false;
let initPromise: Promise<void> | undefined;

export async function initWasm(options: WasmInitOptions = {}): Promise<void> {
  if (initialized) {
    return;
  }

  if (initPromise === undefined) {
    initPromise = (async () => {
      const initAxlsignPromise =
        options.axlsign === undefined
          ? initAxlsign()
          : initAxlsign({ module_or_path: options.axlsign });
      const initCurvePromise =
        options.curve25519 === undefined
          ? initCurve25519()
          : initCurve25519({ module_or_path: options.curve25519 });

      await Promise.all([initAxlsignPromise, initCurvePromise]);
      initialized = true;
    })().catch((error: unknown) => {
      // Allow retry after a failed first initialization attempt.
      initPromise = undefined;
      throw error;
    });
  }

  await initPromise;
}

export function isWasmInitialized(): boolean {
  return initialized;
}

function assertWasmInitialized(): void {
  if (!initialized) {
    throw new Error(
      "WASM runtime is not initialized. Call `await initWasm()` before using cryptographic functions.",
    );
  }
}

export function getAxlsignBindings(): typeof axlsignBindings {
  assertWasmInitialized();
  return axlsignBindings;
}

export function getCurveBindings(): typeof curveBindings {
  assertWasmInitialized();
  return curveBindings;
}
