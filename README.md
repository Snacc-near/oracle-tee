# oracle-tee — `M3 tee-genome-oracle`

The two-layer redaction (*Dual-Layer Redaction*, `ADR-05`) for the **Snacc** `NEAR AI Cloud TEE` genome pipeline:

- **Layer 1 (deterministic local)** — removes identities (NEAR accounts, emails, ed25519 keys) and hides the raw recipe dosages behind a `sha256(raw_formula + salt)` commitment.
- **Layer 2 (optional cloud)** — probes `POST /v1/privacy/redact`; `HTTP 404` (the Spike S2.2 finding) or any failure → falls back to Layer 1 **without failing**.
- **Pipeline output** — `{ chat_id?, request_sha256_hex, payload_terredaksi }` where `request_sha256_hex` = `sha256(request_body)`, consistent with `commit_genome_experiment(strain_id, req_sha256_hex)` on the `snacc-v001.near` contract.

Pure TypeScript (Node ≥ 20, no framework), `node:test` tests.

```bash
npm ci && npm test
```

Spec: `snacc-vault/04 Arsitektur/Snacc - Spec API Backend dan TEE.md` (Stages 1–2, `ADR-05`).
Design ambiguities are recorded in the comments of `src/redact.ts` & `src/pipeline.ts` (A1–A4).
