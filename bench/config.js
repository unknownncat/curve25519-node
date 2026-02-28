export const SUPPORTED_VARIANTS = ["raw", "cached", "copy", "nocopy"];

const DEFAULTS = {
  rounds: 12,
  roundMs: 250,
  warmupMs: 300,
  vectors: 64,
  gc: true,
  json: false,
  jsonFile: "",
  debug: false,
  strict: false,
  verifyDuringBench: false,
  verifyEvery: 64,
  quiet: false,
  variants: ["raw"],
  baseline: "",
  maxRegressionPct: 10,
  failOnRegression: false,
};

function parseNumber(rawValue, min = 1) {
  const num = Number(rawValue);
  if (!Number.isFinite(num)) return null;
  if (num < min) return null;
  return num;
}

function parseVariantList(raw) {
  const values = raw
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
  const unique = [...new Set(values)];
  const invalid = unique.filter((v) => !SUPPORTED_VARIANTS.includes(v));
  if (invalid.length > 0) {
    throw new Error(
      `Unsupported variants: ${invalid.join(", ")}. Supported: ${SUPPORTED_VARIANTS.join(", ")}`
    );
  }
  return unique.length > 0 ? unique : [...DEFAULTS.variants];
}

export function parseArgs(argv = process.argv.slice(2)) {
  const out = {
    ...DEFAULTS,
    variants: [...DEFAULTS.variants],
  };

  for (const arg of argv) {
    if (arg === "--json") {
      out.json = true;
      continue;
    }
    if (arg === "--debug") {
      out.debug = true;
      continue;
    }
    if (arg === "--strict") {
      out.strict = true;
      continue;
    }
    if (arg === "--quiet") {
      out.quiet = true;
      continue;
    }
    if (arg === "--verifyDuringBench") {
      out.verifyDuringBench = true;
      continue;
    }
    if (arg === "--gc") {
      out.gc = true;
      continue;
    }
    if (arg === "--no-gc") {
      out.gc = false;
      continue;
    }
    if (arg === "--failOnRegression") {
      out.failOnRegression = true;
      continue;
    }
    if (!arg.startsWith("--")) continue;

    const [rawKey, rawValue] = arg.slice(2).split("=", 2);
    if (!rawKey || rawValue === undefined) continue;

    if (rawKey === "jsonFile") {
      out.jsonFile = rawValue;
      continue;
    }
    if (rawKey === "baseline") {
      out.baseline = rawValue;
      continue;
    }
    if (rawKey === "variant") {
      out.variants = parseVariantList(rawValue);
      continue;
    }
    if (rawKey === "variants") {
      out.variants = parseVariantList(rawValue);
      continue;
    }

    if (rawKey === "rounds") {
      const parsed = parseNumber(rawValue, 1);
      if (parsed !== null) out.rounds = Math.floor(parsed);
      continue;
    }
    if (rawKey === "roundMs") {
      const parsed = parseNumber(rawValue, 1);
      if (parsed !== null) out.roundMs = parsed;
      continue;
    }
    if (rawKey === "warmupMs") {
      const parsed = parseNumber(rawValue, 1);
      if (parsed !== null) out.warmupMs = parsed;
      continue;
    }
    if (rawKey === "vectors") {
      const parsed = parseNumber(rawValue, 64);
      if (parsed !== null) out.vectors = Math.floor(parsed);
      continue;
    }
    if (rawKey === "verifyEvery") {
      const parsed = parseNumber(rawValue, 1);
      if (parsed !== null) out.verifyEvery = Math.floor(parsed);
      continue;
    }
    if (rawKey === "maxRegressionPct") {
      const parsed = parseNumber(rawValue, 0);
      if (parsed !== null) out.maxRegressionPct = parsed;
      continue;
    }
  }

  if (out.strict) {
    out.verifyDuringBench = true;
  }

  if (out.variants.length === 0) {
    out.variants = [...DEFAULTS.variants];
  }

  return out;
}

export function modeSummary(config) {
  return {
    strict: config.strict,
    debug: config.debug,
    json: config.json,
    verifyDuringBench: config.verifyDuringBench,
    verifyEvery: config.verifyEvery,
    gcBetweenRounds: config.gc,
    variants: config.variants,
    failOnRegression: config.failOnRegression,
    baseline: config.baseline || null,
  };
}
