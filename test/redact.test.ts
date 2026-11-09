// TEE-104 — Dual-Layer Redaction unit tests (node:test, no framework).
// The fixtures come verbatim from spec §1 Stages 1–2 (snacc-vault/04 Arsitektur/Snacc - Spec API Backend dan TEE.md).

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import {
  maskIdentity,
  newSaltHex,
  normalizeRatios,
  redactLayer1,
  sha256Hex,
} from "../src/redact.js";
import {
  CLOUD_REDACT_ENDPOINT,
  TEE_MODEL,
  TEE_SYSTEM_PROMPT,
  cloudRedact,
  runGenomeRedactionPipeline,
} from "../src/pipeline.js";

// The spec Stage 2 example payload + identity contamination (for the mask test).
const RAW_FORMULA = "Ignis-Spore: 3, Lumin-Spore: 2, Sulfuric-Redactase: 1";
const PAYLOAD =
  "Alkemis myth.core.near (email myth@example.com, key ed25519:9xCwKrN5SznYzRnQ1tFg4YhWzv6ePqU2aBcDdEfGgHhJjKkMmNnPpQqRrSsTtUuVv) | " +
  "Sequence: [Ignis-Spore: 3, Lumin-Spore: 2, Sulfuric-Redactase: 1, Thermal-Shock: 395K]";

function makeStubFetch(status: number, body: unknown, capture?: { url: string; init: RequestInit }[]) {
  return (async (url: string, init: RequestInit) => {
    if (capture) capture.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
}

describe("TEE-101 — the deterministic local Layer 1", () => {
  test("maskIdentity removes NEAR accounts, emails, and ed25519 keys", () => {
    const out = maskIdentity(PAYLOAD);
    assert.ok(!out.includes("myth.core.near"));
    assert.ok(!out.includes("myth@example.com"));
    assert.ok(!out.includes("ed25519:"));
    assert.ok(out.includes("[REDACTED_ACCOUNT]"));
    assert.ok(out.includes("[REDACTED_EMAIL]"));
    assert.ok(out.includes("[REDACTED_KEY]"));
    // The dosages are untouched by maskIdentity (that is the commitment's job).
    assert.ok(out.includes("Ignis-Spore: 3"));
  });

  test("normalizeRatios produces normalized ratios (the spec example)", () => {
    const r = normalizeRatios(RAW_FORMULA);
    assert.deepEqual(r, { "Ignis-Spore": 0.5, "Lumin-Spore": 0.333333, "Sulfuric-Redactase": 0.166667 });
  });

  test("normalizeRatios is empty when there are no dosages", () => {
    assert.deepEqual(normalizeRatios("no numbers here"), {});
  });

  test("the commitment = sha256(raw_formula + salt), deterministic per salt", () => {
    const salt = "ab".repeat(16);
    const a = redactLayer1(PAYLOAD, RAW_FORMULA, salt);
    const b = redactLayer1(PAYLOAD, RAW_FORMULA, salt);
    assert.equal(a.commitment_hex, b.commitment_hex);
    assert.equal(a.commitment_hex, sha256Hex(RAW_FORMULA + salt));
    assert.match(a.commitment_hex, /^[0-9a-f]{64}$/);
    // A different salt → a different commitment.
    const c = redactLayer1(PAYLOAD, RAW_FORMULA, "cd".repeat(16));
    assert.notEqual(a.commitment_hex, c.commitment_hex);
  });

  test("newSaltHex is a random 16 bytes (32 hex chars), different between calls", () => {
    const s1 = newSaltHex();
    const s2 = newSaltHex();
    assert.match(s1, /^[0-9a-f]{32}$/);
    assert.notEqual(s1, s2);
  });

  test("payload_terredaksi: raw dosages replaced by the commitment, PII removed, no warnings", () => {
    const out = redactLayer1(PAYLOAD, RAW_FORMULA, "ab".repeat(16));
    assert.ok(!out.payload_terredaksi.includes("Ignis-Spore: 3"));
    assert.ok(out.payload_terredaksi.includes("StoichiometryCommitment: " + out.commitment_hex));
    assert.ok(!out.payload_terredaksi.includes("myth.core.near"));
    assert.deepEqual(out.warnings, []);
    assert.deepEqual(out.ratios, normalizeRatios(RAW_FORMULA));
  });

  test("raw_formula not verbatim in the payload → a warning, the commitment is still built", () => {
    const out = redactLayer1("payload without a formula", RAW_FORMULA, "ab".repeat(16));
    assert.equal(out.warnings.length, 1);
    assert.match(out.commitment_hex, /^[0-9a-f]{64}$/);
  });
});

describe("TEE-102 — Layer 2 cloud redaction + fallback", () => {
  test("HTTP 404 -> fallback local_deterministic_sha256 + warning (Spike S2.2)", async () => {
    const r = await cloudRedact("x", { fetchImpl: makeStubFetch(404, {}) as typeof fetch });
    assert.equal(r.text, null);
    assert.equal(r.mode, "local_deterministic_sha256");
    assert.match(r.warning ?? "", /404/);
  });

  test("HTTP 200 with a `redacted` field → the cloud mode", async () => {
    const r = await cloudRedact("x", {
      fetchImpl: makeStubFetch(200, { redacted: "cloud-result" }) as typeof fetch,
    });
    assert.equal(r.text, "cloud-result");
    assert.equal(r.mode, "cloud");
    assert.equal(r.warning, undefined);
  });

  test("HTTP 500 and network errors → a fail-free fallback", async () => {
    const r500 = await cloudRedact("x", { fetchImpl: makeStubFetch(500, {}) as typeof fetch });
    assert.equal(r500.mode, "local_deterministic_sha256");
    const rNet = await cloudRedact("x", {
      fetchImpl: (async () => {
        throw new Error("fetch failed");
      }) as unknown as typeof fetch,
    });
    assert.equal(rNet.mode, "local_deterministic_sha256");
    assert.match(rNet.warning ?? "", /fetch failed/);
  });

  test("the Layer 2 request body matches the spec: { model, input } to the official endpoint", async () => {
    const capture: { url: string; init: RequestInit }[] = [];
    await cloudRedact("payload-x", {
      fetchImpl: makeStubFetch(404, {}, capture) as typeof fetch,
    });
    assert.equal(capture.length, 1);
    assert.equal(capture[0]?.url, CLOUD_REDACT_ENDPOINT);
    const body = JSON.parse(String(capture[0]?.init.body) ?? "{}") as Record<string, string>;
    assert.equal(body.model, TEE_MODEL);
    assert.equal(body.input, "payload-x");
  });
});

describe("TEE-103 — the pipeline is consistent with commit_genome_experiment", () => {
  test("request_sha256_hex = sha256(request_body); the payload is free of PII & raw dosages", async () => {
    const out = await runGenomeRedactionPipeline({
      strainId: 1,
      payloadText: PAYLOAD,
      rawFormula: RAW_FORMULA,
      saltHex: "ab".repeat(16),
    });
    assert.equal(out.request_sha256_hex, sha256Hex(out.request_body));
    assert.match(out.request_sha256_hex, /^[0-9a-f]{64}$/);
    assert.ok(!out.payload_terredaksi.includes("myth.core.near"));
    assert.ok(!out.payload_terredaksi.includes("Ignis-Spore: 3"));
    assert.equal(out.redaction_mode, "local_deterministic_sha256");
    // The Stage 2 request structure matches the spec exactly: a locked model, temperature 0, 2 messages.
    const parsed = JSON.parse(out.request_body) as {
      model: string;
      temperature: number;
      messages: Array<{ role: string; content: string }>;
    };
    assert.equal(parsed.model, TEE_MODEL);
    assert.equal(parsed.temperature, 0);
    assert.equal(parsed.messages.length, 2);
    assert.equal(parsed.messages[0]?.content, TEE_SYSTEM_PROMPT);
    assert.ok(parsed.messages[1]?.content.includes("Strain #1"));
    assert.ok(parsed.messages[1]?.content.includes(out.commitment_hex));
  });

  test("a successful Layer 2 → the user payload uses the cloud result, the cloud mode", async () => {
    const out = await runGenomeRedactionPipeline({
      strainId: 7,
      payloadText: "formula: " + RAW_FORMULA,
      rawFormula: RAW_FORMULA,
      saltHex: "ab".repeat(16),
      cloud: { fetchImpl: makeStubFetch(200, { redacted: "BERSIH" }) as typeof fetch },
    });
    assert.equal(out.redaction_mode, "cloud");
    assert.ok(out.payload_terredaksi.includes("BERSIH"));
    // The Layer 1 commitment still travels into the request.
    assert.ok(out.request_body.includes(out.commitment_hex));
  });

  test("a Layer 2 404 → the pipeline still succeeds with a warning (it never fails)", async () => {
    const out = await runGenomeRedactionPipeline({
      strainId: 2,
      payloadText: PAYLOAD,
      rawFormula: RAW_FORMULA,
      saltHex: "ab".repeat(16),
      cloud: { fetchImpl: makeStubFetch(404, {}) as typeof fetch },
    });
    assert.equal(out.redaction_mode, "local_deterministic_sha256");
    assert.ok(out.warnings.some((w) => w.includes("404")));
    assert.match(out.request_sha256_hex, /^[0-9a-f]{64}$/);
  });
});

// RES-102 — the Layer 1.5 `/v1/privacy/classify` before redact (the true Dual-Layer).
import { cloudClassify } from "../src/pipeline.js";

describe("RES-102 — the Layer 1.5 classify before redact", () => {
  test("HTTP 200 with a label → the classification is recorded", async () => {
    const r = await cloudClassify("x", {
      fetchImpl: makeStubFetch(200, { label: "trade-secret" }) as typeof fetch,
    });
    assert.equal(r.label, "trade-secret");
    assert.equal(r.warning, undefined);
  });

  test("HTTP 404 → a null label + a warning, it does not throw", async () => {
    const r = await cloudClassify("x", { fetchImpl: makeStubFetch(404, {}) as typeof fetch });
    assert.equal(r.label, null);
    assert.match(r.warning ?? "", /404/);
  });

  test("pipeline: classify runs BEFORE redact and the result lands in PipelineOutput", async () => {
    const order: string[] = [];
    const fetchImpl = (async (url: string) => {
      if (String(url).includes("classify")) {
        order.push("classify");
        return new Response(JSON.stringify({ sensitivity: "confidential" }), { status: 200 });
      }
      order.push("redact");
      return new Response(JSON.stringify({}), { status: 404 });
    }) as unknown as typeof fetch;
    const out = await runGenomeRedactionPipeline({
      strainId: 1,
      payloadText: "recipe: identity=ratio 1:2",
      rawFormula: "1:2",
      saltHex: "a".repeat(32),
      cloud: { fetchImpl },
    });
    assert.deepEqual(order, ["classify", "redact"], "the order must be classify -> redact");
    assert.equal(out.classification, "confidential");
  });

  test("the pipeline keeps running when classify fails (a fallback)", async () => {
    const fetchImpl = (async (url: string) => {
      if (String(url).includes("classify")) throw new Error("network down");
      return new Response(JSON.stringify({}), { status: 404 });
    }) as unknown as typeof fetch;
    const out = await runGenomeRedactionPipeline({
      strainId: 1,
      payloadText: "x",
      rawFormula: "y",
      saltHex: "b".repeat(32),
      cloud: { fetchImpl },
    });
    assert.equal(out.classification, null);
    assert.ok(out.warnings.some((w) => w.includes("layer1.5")), "the classify warning is recorded");
  });
});
