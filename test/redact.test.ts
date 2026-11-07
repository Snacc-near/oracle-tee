// TEE-104 — unit test Dual-Layer Redaction (node:test, tanpa framework).
// Fixture diambil persis dari spec §1 Tahap 1–2 (snacc-vault/04 Arsitektur/Snacc - Spec API Backend dan TEE.md).

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

// Payload contoh spec Tahap 2 + kontaminasi identitas (untuk uji mask).
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

describe("TEE-101 — Layer 1 deterministik lokal", () => {
  test("maskIdentity menghapus akun NEAR, email, dan kunci ed25519", () => {
    const out = maskIdentity(PAYLOAD);
    assert.ok(!out.includes("myth.core.near"));
    assert.ok(!out.includes("myth@example.com"));
    assert.ok(!out.includes("ed25519:"));
    assert.ok(out.includes("[REDACTED_ACCOUNT]"));
    assert.ok(out.includes("[REDACTED_EMAIL]"));
    assert.ok(out.includes("[REDACTED_KEY]"));
    // Takaran tidak disentuh maskIdentity (itu tugas commitment).
    assert.ok(out.includes("Ignis-Spore: 3"));
  });

  test("normalizeRatios menghasilkan rasio ternormalisasi (contoh spec)", () => {
    const r = normalizeRatios(RAW_FORMULA);
    assert.deepEqual(r, { "Ignis-Spore": 0.5, "Lumin-Spore": 0.333333, "Sulfuric-Redactase": 0.166667 });
  });

  test("normalizeRatios kosong bila tidak ada takaran", () => {
    assert.deepEqual(normalizeRatios("tidak ada angka di sini"), {});
  });

  test("komitmen = sha256(raw_formula + salt), deterministik per salt", () => {
    const salt = "ab".repeat(16);
    const a = redactLayer1(PAYLOAD, RAW_FORMULA, salt);
    const b = redactLayer1(PAYLOAD, RAW_FORMULA, salt);
    assert.equal(a.commitment_hex, b.commitment_hex);
    assert.equal(a.commitment_hex, sha256Hex(RAW_FORMULA + salt));
    assert.match(a.commitment_hex, /^[0-9a-f]{64}$/);
    // Salt berbeda -> komitmen berbeda.
    const c = redactLayer1(PAYLOAD, RAW_FORMULA, "cd".repeat(16));
    assert.notEqual(a.commitment_hex, c.commitment_hex);
  });

  test("newSaltHex acak 16 byte (32 hex char), tidak sama antar panggilan", () => {
    const s1 = newSaltHex();
    const s2 = newSaltHex();
    assert.match(s1, /^[0-9a-f]{32}$/);
    assert.notEqual(s1, s2);
  });

  test("payload_terredaksi: takaran mentah diganti komitmen, PII terhapus, warning kosong", () => {
    const out = redactLayer1(PAYLOAD, RAW_FORMULA, "ab".repeat(16));
    assert.ok(!out.payload_terredaksi.includes("Ignis-Spore: 3"));
    assert.ok(out.payload_terredaksi.includes("StoichiometryCommitment: " + out.commitment_hex));
    assert.ok(!out.payload_terredaksi.includes("myth.core.near"));
    assert.deepEqual(out.warnings, []);
    assert.deepEqual(out.ratios, normalizeRatios(RAW_FORMULA));
  });

  test("raw_formula tidak verbatim di payload -> warning, komitmen tetap dibuat", () => {
    const out = redactLayer1("payload tanpa formula", RAW_FORMULA, "ab".repeat(16));
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

  test("HTTP 200 dengan field `redacted` -> mode cloud", async () => {
    const r = await cloudRedact("x", {
      fetchImpl: makeStubFetch(200, { redacted: "hasil-cloud" }) as typeof fetch,
    });
    assert.equal(r.text, "hasil-cloud");
    assert.equal(r.mode, "cloud");
    assert.equal(r.warning, undefined);
  });

  test("HTTP 500 dan error jaringan -> fallback tanpa gagal", async () => {
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

  test("request body Layer 2 sesuai spec: { model, input } ke endpoint resmi", async () => {
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

describe("TEE-103 — pipeline konsisten commit_genome_experiment", () => {
  test("request_sha256_hex = sha256(request_body); payload bebas PII & takaran mentah", async () => {
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
    // Struktur request Tahap 2 persis spec: model terkunci, temperature 0, 2 messages.
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

  test("Layer 2 sukses -> payload user memakai hasil cloud, mode cloud", async () => {
    const out = await runGenomeRedactionPipeline({
      strainId: 7,
      payloadText: "formula: " + RAW_FORMULA,
      rawFormula: RAW_FORMULA,
      saltHex: "ab".repeat(16),
      cloud: { fetchImpl: makeStubFetch(200, { redacted: "BERSIH" }) as typeof fetch },
    });
    assert.equal(out.redaction_mode, "cloud");
    assert.ok(out.payload_terredaksi.includes("BERSIH"));
    // Komitmen Layer 1 tetap terbawa ke request.
    assert.ok(out.request_body.includes(out.commitment_hex));
  });

  test("Layer 2 404 -> pipeline tetap sukses dengan warning (tidak pernah gagal)", async () => {
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
