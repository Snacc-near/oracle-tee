# oracle-tee — `M3 tee-genome-oracle`

Redaksi dua lapis (*Dual-Layer Redaction*, `ADR-05`) untuk pipeline genome `NEAR AI Cloud TEE` proyek **Snacc**:

- **Layer 1 (deterministik lokal)** — hapus identitas (akun NEAR, email, kunci ed25519) dan sembunyikan takaran resep mentah di balik komitmen `sha256(raw_formula + salt)`.
- **Layer 2 (opsional cloud)** — probe `POST /v1/privacy/redact`; `HTTP 404` (temuan Spike S2.2) atau kegagalan apa pun → fallback ke Layer 1 **tanpa gagal**.
- **Output pipeline** — `{ chat_id?, request_sha256_hex, payload_terredaksi }` di mana `request_sha256_hex` = `sha256(request_body)` konsisten dengan `commit_genome_experiment(strain_id, req_sha256_hex)` di kontrak `snacc-v001.near`.

TypeScript murni (Node ≥ 20, tanpa framework), test `node:test`.

```bash
npm ci && npm test
```

Spec: `snacc-vault/04 Arsitektur/Snacc - Spec API Backend dan TEE.md` (Tahap 1–2, `ADR-05`).
Ambiguitas desain dicatat di komentar `src/redact.ts` & `src/pipeline.ts` (A1–A4).
