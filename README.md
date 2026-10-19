# PolicyProof

**Lock operational rules. Commit public evidence. Inspect independent GenLayer consensus.**

PolicyProof is a GenLayer Intelligent Contract and working web application for checking public operational evidence against a fixed policy. Organizations define a scope and explicit requirements. Participants commit public evidence with exact SHA-256 hashes. GenLayer leaders and validators independently retrieve the same documents, assess every criterion, and reach consensus on **PASS / FAIL / INCONCLUSIVE**.

- Website: https://policyproof.ansaf1st34.chatgpt.site (owner-private initial publication)
- Contract: https://explorer-studio.genlayer.com/address/0x37b36cBdB694c3B76Bf7F482917d5e774c4CF409
- Network: GenLayer Studionet, chain 61999, RPC `https://studio.genlayer.com/api`
- Source: [`contracts/policyproof.py`](contracts/policyproof.py)
- Architecture and limits: [`docs/architecture.md`](docs/architecture.md)
- Machine-readable deployment checks: [`docs/live-verification.json`](docs/live-verification.json)

## Why GenLayer is central

Checking hashes and timestamps alone cannot determine whether a natural-language incident report supports a written operational requirement. PolicyProof combines deterministic commitments and access control with semantic criterion assessment. Each validator independently fetches documents, verifies the exact bytes and repeats the model assessment. Validator comparison checks every normalized criterion state and integrity result, not only a leader-selected overall verdict or output format. The overall verdict is derived by code after semantic extraction.

## Try the pilot

1. Open the website. No wallet is required to inspect finalized policies, evidence, criterion findings and revision histories.
2. Select the synthetic incident cases. INC-42 meets the response policy; INC-43 contains explicit timing violations and an embedded prompt-injection attempt; INC-44 omits customer-notice evidence.
3. Click **Verify public bytes** to independently hash the committed bundle and its source documents in your browser.
4. For writes, connect your own MetaMask-compatible wallet on Studionet. Connecting requests accounts only. Review the exact public request separately before signing.
5. Creating policies or assessments needs an administrator-allocated pilot slot. Anyone may evaluate a pending assessment. No rewards, deposits or token escrow are used.

The Studio built-in account deploys and exercises the contract inside Studio. Its key is never exported or put in the website. Visitors use their own wallet to sign website writes.

## Contract API

| Method | Purpose |
| --- | --- |
| `create_policy(id, policy_json)` | Lock name, scope and 1–6 unique criteria; admitted creators only. |
| `submit_assessment(policy_id, id, subject, period, url, sha256)` | Commit evidence to an existing policy; admitted participants, including a different account from the policy owner. |
| `evaluate(id)` | Independently fetch and assess the pending revision through full consensus; permissionless. |
| `revise_evidence(id, url, sha256)` | Submitter-only, distinct bundle hash, up to three revisions; prior reviews retained. |
| `configure_account(account, policies, assessments)` | Administrator assigns reserved storage slots; cannot reclaim used slots. |
| `get_policy`, `get_assessment`, `get_index`, `get_capacity` | Public JSON reads. |

## Evidence schema

Use a raw.githubusercontent.com URL pinned to a full Git commit. Every file must be at most 16,000 bytes. Supported extensions: `.json`, `.txt`, `.md`. Branch names, arbitrary hosts and query strings are rejected.

```json
{
  "schema": "policyproof/v1",
  "synthetic": true,
  "assessment_id": "inc-42",
  "policy_sha256": "<SHA-256 of canonical locked policy JSON>",
  "subject": "Aurora service, incident INC-42",
  "period": "2026-10-01 UTC",
  "sources": [
    {"url": "https://raw.githubusercontent.com/OWNER/REPO/FULL_COMMIT/report.txt", "sha256": "<exact file SHA-256>"}
  ]
}
```

See actual committed examples in [`evidence/`](evidence). Replace placeholders with real full-length hashes. Canonical policy JSON sorts object keys recursively, uses ASCII escaping and separators `,` and `:` without whitespace. Criterion array order stays fixed.

## Run checks

Python 3.12 and Node 22 are supported.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-test.txt
genvm-lint contracts/policyproof.py
pytest tests -q
cd web
npm ci
npm test
npm run check
npm run build
```

Tests use the official GenLayer Direct Mode VM, not a hand-built contract mock. External web/model responses are mocked for deterministic boundary tests; live Studionet evidence is recorded separately. GitHub Actions runs contract checks, browser-provider safety tests, TypeScript checking and the production build.

`node scripts/check-live.mjs` checks exact deployed source, full-consensus execution receipts, finalized state, expected outcomes and public source commitments. It is read-only and requires no private key.

## Boundaries

A PASS assesses the committed documents under the locked policy; it is not independent authentication of real operations. All pilot incident documents are synthetic and visibly labeled. Missing or ambiguous support gives UNKNOWN; explicit contradictions give VIOLATED. Any VIOLATED criterion yields FAIL; otherwise any UNKNOWN yields INCONCLUSIVE; otherwise PASS. Integrity failures give INCONCLUSIVE with an error code. Temporary retrieval/model failures revert without consuming a revision and can be retried.

The pilot has finite reserved storage and three revisions per assessment. The website never substitutes fake success data when RPC reads fail. Studionet may reset and development code may be changed; verify deployed-source correspondence before relying on the pilot. See the architecture document for detailed resource and threat boundaries.
