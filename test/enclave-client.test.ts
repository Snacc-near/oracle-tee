// TEE-105..108 tests — the enclave client (a mock fetch for the flows; REAL vectors for ed25519).
// The real vectors: spike S1.8/S2.6 (chat_id c895b8f389fe45f3b369417a6de52536).

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

test("verifyEd25519 accepts the REAL spike S2.6 vector", () => {
  assert.equal(verifyEd25519(PUBKEY, SIGNED_TEXT, SIG), true);
});

test("verifyEd25519 rejects a signature flipped by 1 byte", () => {
  const flipped = "0" + SIG.slice(1);
  assert.equal(verifyEd25519(PUBKEY, SIGNED_TEXT, flipped), false);
});

test("validateMutation rejects a shift > 1500 and a vitality > 500", () => {
  assert.throws(() => validateMutation({ efficiency_shift_bps: 1501, vitality_bonus: 0 }), /ERR_GUARDRAIL_SHIFT/);
  assert.throws(() => validateMutation({ efficiency_shift_bps: 0, vitality_bonus: 501 }), /ERR_GUARDRAIL_VITALITY/);
  validateMutation({ efficiency_shift_bps: -1500, vitality_bonus: 500 });
});

test("runGenomeExperiment: a successful flow (mock) + caching", async () => {
  clearExperimentCache();
  let chatCalls = 0;
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => { chatCalls++; return ok(ENVELOPE); },
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
  });
  const r = await runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true });
  assert.equal(r.chatId, "chat-abc");
  // signedText = the local reconstruction over the mock body (the S2.6 format); the real vectors are tested separately.
  assert.equal(r.signedText, `z-ai/glm-5.3-flash:${REQ_SHA}:${r.rawResponseSha256}`);
  assert.equal(r.mutation.efficiency_shift_bps, 450);
  assert.equal(r.mutation.vitality_bonus, 200);
  // cache: the second call does not touch the network again
  const r2 = await runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true });
  assert.equal(r2.chatId, "chat-abc");
  assert.equal(chatCalls, 1);
});

test("runGenomeExperiment: a server signed_text mismatch -> rejected", async () => {
  clearExperimentCache();
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ text: "wrong-text", signature: SIG, signing_address: PUBKEY })),
  });
  await assert.rejects(
    () => runGenomeExperiment(fakePipeline(), { fetchImpl, skipSignatureVerification: true }),
    /ERR_TEE_SIGNED_TEXT_MISMATCH/,
  );
});

test("runGenomeExperiment: the ed25519 verification fails (a mock body) -> rejected", async () => {
  clearExperimentCache();
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
    "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ text: SIGNED_TEXT, signature: SIG, signing_address: PUBKEY })),
  });
  // The signedText from the local reconstruction over the mock body MUST hash differently from the real vector,
  // so the cryptographic verification fails — that is exactly what proves there is no way through.
  await assert.rejects(
    () => runGenomeExperiment(fakePipeline(), { fetchImpl }),
    /ERR_TEE_SIGNED_TEXT_MISMATCH|ERR_TEE_RESPONSE_HASH_OR_ED25519_MISMATCH/,
  );
});

test("runGenomeExperiment: a mutation outside the I-03 guardrail -> rejected", async () => {
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

test("fetchAttestationReport passes the JSON through as-is", async () => {
  const fetchImpl = mockFetch({
    "https://cloud-api.near.ai/v1/attestation/report": () => ok(JSON.stringify({ attestation: "ok", quote: "hex" })),
  });
  const rep = (await fetchAttestationReport({ fetchImpl })) as { attestation: string };
  assert.equal(rep.attestation, "ok");
});

// RES-101 — the official NEAR AI SDK path: every call via the SDK client + verifyResponse.
import { runGenomeExperimentViaSdk, type SdkClientLike } from "../src/enclave-client.js";

test("RES-101: runGenomeExperimentViaSdk — calls via client.fetch + verifyResponse(chatId)", async () => {
  clearExperimentCache();
  const called: string[] = [];
  const client: SdkClientLike = {
    fetch: mockFetch({
      "https://cloud-api.near.ai/v1/chat/completions": () => ok(ENVELOPE),
      "https://cloud-api.near.ai/v1/signature/": () => ok(JSON.stringify({ signature: SIG, signing_address: PUBKEY })),
    }) as unknown as SdkClientLike["fetch"],
    verifyResponse: async (id: string) => {
      called.push(id);
      return { signatureKind: "ed25519" };
    },
  };
  const r = await runGenomeExperimentViaSdk(fakePipeline(), {
    apiKey: "test",
    client,
    skipSignatureVerification: true,
  });
  assert.equal(r.chatId, "chat-abc");
  assert.equal(r.sdkVerified, true);
  assert.deepEqual(called, ["chat-abc"], "verifyResponse is called with the chatId");
});

test("RES-101: a failed verifyResponse -> sdkVerified false, the local proof stays intact", async () => {
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
    apiKey: "test",
    client,
    skipSignatureVerification: true,
  });
  assert.equal(r.sdkVerified, false);
  assert.equal(r.chatId, "chat-abc", "the experiment result still exists");
  assert.ok(r.rawResponseSha256.length === 64, "the res sha is still computed");
});
