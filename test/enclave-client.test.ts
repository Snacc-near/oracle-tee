// Test TEE-105..108 — klien enclave (mock fetch untuk alur; vektor RIIL untuk ed25519).
// Vektor rial: spike S1.8/S2.6 (chat_id c895b8f389fe45f3b369417a6de52536).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateMutation,
  verifyEd25519,
  runGenomeExperiment,
  fetchAttestationReport,
  clearExperimentCache,
} from "../src/enclave-client.js";
import type { PipelineOutput } from "../src/pipeline.js";

const REQ_SHA = "d06094a574a9e212b6756e3fb67457ec3a6fff9a4ff83fb3f48935e852569bb1";
const RES_SHA = "9014e73a4ed9d1c2234b4d04c4d0897330a9c2b52b10e60fb5b2e3d07f91a21c";
const PUBKEY = "5a0210f2442c79355784f9de021985429561da5bacc3a4424b01ac52b7e0caff";
const SIG = "23f722d80dc1eb3b74a9523d57bb8e168700bc6fe6a22e97ad58254b3e353e0d05c04e4af4fa479a769cd18e0d5e44034a94c71370507a1c7f3fc75e2ce1c20d";
const SIGNED_TEXT = `z-ai/glm-5.3-flash:${REQ_SHA}:${RES_SHA}`;

function fakePipeline(): PipelineOutput {
  return {
    request_sha256_hex: REQ_SHA,
    request_body: '{"model":"z-ai/glm-5.3-flash","temperature":0,"messages":[]}',
    payload_terredaksi: "redacted",
    redaction_mode: "local_deterministic_sha256",
    warnings: [],
    commitment_hex: "ab",
    salt_hex: "cd",
  };
}

const ENVELOPE = JSON.stringify({
  id: "chat-abc",
  choices: [{ message: { content: '{"efficiency_shift_bps":450,"vitality_bonus":200,"phenotype_trait":"Thermo-Aureate"}' } }],
});

function mockFetch(handlers: Record<string, () => Response>) {
  return async (url: string, _init: RequestInit): Promise<Response> => {
    for (const [prefix, fn] of Object.entries(handlers)) {
      if (url.startsWith(prefix)) return fn();
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
}

const ok = (body: string) => new Response(body, { status: 200 });

test("verifyEd25519 meluluskan vektor RIIL spike S2.6", () => {
  assert.equal(verifyEd25519(PUBKEY, SIGNED_TEXT, SIG), true);
});

test("verifyEd25519 menolak signature yang diubah 1 byte", () => {
  const flipped = "0" + SIG.slice(1);
  assert.equal(verifyEd25519(PUBKEY, SIGNED_TEXT, flipped), false);
});

test("validateMutation menolak shift > 1500 dan vitality > 500", () => {
  assert.throws(() => validateMutation({ efficiency_shift_bps: 1501, vitality_bonus: 0 }), /ERR_GUARDRAIL_SHIFT/);
  assert.throws(() => validateMutation({ efficiency_shift_bps: 0, vitality_bonus: 501 }), /ERR_GUARDRAIL_VITALITY/);
  validateMutation({ efficiency_shift_bps: -1500, vitality_bonus: 500 });
});

test("runGenomeExperiment: alur sukses (mock) + caching", async () => {
  clearExperimentCache();
  let chatCalls = 0;
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => { chatCalls++; return ok(ENVELOPE); },
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
  });
  const r = await runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true });
  assert.equal(r.chatId, "chat-abc");
  // signedText = rekonstruksi lokal atas body mock (format S2.6); vektor rial diuji terpisah.
  assert.equal(r.signedText, `z-ai/glm-5.3-flash:${REQ_SHA}:${r.rawResponseSha256}`);
  assert.equal(r.mutation.efficiency_shift_bps, 450);
  assert.equal(r.mutation.vitality_bonus, 200);
  // cache: panggilan kedua tidak menyentuh jaringan lagi
  const r2 = await runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true });
  assert.equal(r2.chatId, "chat-abc");
  assert.equal(chatCalls, 1);
});

test("runGenomeExperiment: signed_text server tidak cocok -> ditolak", async () => {
  clearExperimentCache();
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ text: "teks-salah", signature: SIG, signing_address: PUBKEY })),
  });
  await assert.rejects(
    () => runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true }),
    /ERR_TEE_SIGNED_TEXT_MISMATCH/,
  );
});

test("runGenomeExperiment: verifikasi ed25519 gagal (mock body) -> ditolak", async () => {
  clearExperimentCache();
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ text: SIGNED_TEXT, signature: SIG, signing_address: PUBKEY })),
  });
  // signedText hasil rekonstruksi lokal atas body mock PASTI berbeda hash-nya dari vektor rial,
  // sehingga verifikasi kriptografis gagal — inilah yang membuktikan tidak ada jalan lolos.
  await assert.rejects(
    () => runGenomeExperiment(fakePipeline(), { fetchImpl }),
    /ERR_TEE_SIGNED_TEXT_MISMATCH|ERR_TEE_RESPONSE_HASH_OR_ED25519_MISMATCH/,
  );
});

test("runGenomeExperiment: mutasi di luar guardrail I-03 -> ditolak", async () => {
  clearExperimentCache();
  const bad = JSON.stringify({ id: "chat-x", choices: [{ message: { content: '{"efficiency_shift_bps":9000,"vitality_bonus":0}' } }] });
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => ok(bad),
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
  });
  await assert.rejects(
    () => runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true }),
    /ERR_GUARDRAIL_SHIFT/,
  );
});

test("fetchAttestationReport meneruskan JSON apa adanya", async () => {
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/attestation/report": () => ok(JSON.stringify({ attestation: "ok", quote: "hex" })),
  });
  const rep = (await fetchAttestationReport({ fetchImpl })) as { attestation: string };
  assert.equal(rep.attestation, "ok");
});

// RES-101 — jalur SDK resmi NEAR AI: semua panggilan via klien SDK + verifyResponse.
import { runGenomeExperimentViaSdk, type SdkClientLike } from "../src/enclave-client.js";

test("RES-101: runGenomeExperimentViaSdk — panggilan via client.fetch + verifyResponse(chatId)", async () => {
  clearExperimentCache();
  const dipanggil: string[] = [];
  const client: SdkClientLike = {
    fetch: mockFetch({
      "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
      "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
    }) as unknown as SdkClientLike["fetch"],
    verifyResponse: async (id: string) => {
      dipanggil.push(id);
      return { signatureKind: "ed25519" };
    },
  };
  const r = await runGenomeExperimentViaSdk(fakePipeline(), {
    apiKey: "uji",
    client,
    skipSignatureVerification: true,
  });
  assert.equal(r.chatId, "chat-abc");
  assert.equal(r.sdkVerified, true);
  assert.deepEqual(dipanggil, ["chat-abc"], "verifyResponse dipanggil dengan chatId");
});

test("RES-101: verifyResponse gagal -> sdkVerified false, bukti lokal tetap utuh", async () => {
  clearExperimentCache();
  const client: SdkClientLike = {
    fetch: mockFetch({
      "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
      "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
    }) as unknown as SdkClientLike["fetch"],
    verifyResponse: async () => {
      throw new Error("signature mismatch");
    },
  };
  const r = await runGenomeExperimentViaSdk(fakePipeline(), {
    apiKey: "uji",
    client,
    skipSignatureVerification: true,
  });
  assert.equal(r.sdkVerified, false);
  assert.equal(r.chatId, "chat-abc", "hasil eksperimen tetap ada");
  assert.ok(r.rawResponseSha256.length === 64, "res sha tetap dihitung");
});
