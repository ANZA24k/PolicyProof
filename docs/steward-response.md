# PolicyProof — response for reassessment

The recovery, historical evidence and public frontend changes are implemented and deployed as protocol v2.

## 1. Permanent encoding failures and controlled recovery

`retrieve()` now distinguishes a hash-verified UTF-8 decoding failure as `INVALID_UTF8`. Evaluation records INCONCLUSIVE with this permanent integrity code. The assessment owner can then append a corrected evidence revision; prior history remains unchanged. Repeated evaluation of a reviewed revision still reverts. Genuine temporary retrieval/model errors remain retryable and do not consume a revision.

The official Direct Mode suite now passes **57 tests**. New coverage includes malformed UTF-8 bundles and source documents, repeated evaluation, unauthorized revision rejection, valid recovery, packet forgery, alternative grounded validator excerpts, and historical reconstruction after external source changes and across successive revisions.

Live proof at the new contract: https://explorer-studio.genlayer.com/address/0x910300ca08d112c7335691ED6C389746ca26Cf86

- `inc-42`: revision 1 INCONCLUSIVE / INVALID_UTF8 → revision 2 PASS → revision 3 PASS with a changed source commitment.
- `invalid-source`: revision 1 INCONCLUSIVE / INVALID_UTF8 → corrected revision 2 PASS.
- Deliberate repeated `inc-42` evaluation finalized with GenVM ERROR / “Revision already reviewed”; history remains three entries.

## 2. Durable criterion-level historical evidence

Every successful semantic evaluation retains a SHA-256 committed `policyproof/audit-v2` packet in contract history: original policy, exact bundle text, source snapshots, source indices, exact supporting quotations, and corresponding content commitments. UNKNOWN findings carry source -1 and no claimed quote.

Validators still independently retrieve and semantically assess every criterion. They verify the proposed packet against independently fetched snapshots and require matching criterion classifications and immutable inputs; independently valid quote wording may differ. A final deterministic packet check runs before storage. Source snapshots total at most 24,000 bytes per review, canonical packets at most 260,000 bytes, with at most three revisions per assessment.

The public app displays citations and preserved snapshots, verifies historical packets without external source requests, and exports complete audit JSON. INC-42 revisions 2 and 3 reconstruct independently with different source hashes. The actual browser-exported revision 2 packet is preserved in `docs/audit-example-revision-2.json` and reverified offline. Changed/unavailable-source reconstruction and successive revision preservation are also exercised in Direct Mode tests.

## 3. Public frontend, source correspondence and execution evidence

Public website: https://policyproof.ansaf1st34.chatgpt.site

Publication metadata now records `audience: public`. Browser review reached the app without a sign-in wall, discovered finalized PASS/FAIL/INCONCLUSIVE records, verified live source hashes, verified both historical packets and downloaded audit JSON. Screenshots and exact steps are in `docs/browser-verification.md` and `docs/browser-evidence/`.

The available browser has no MetaMask/EIP-1193 provider. Real MetaMask extension signing was not performed and is not claimed. Its missing-provider handling was verified. The separate, clearly labeled browser simulation exercises the production wallet functions for connection, network/account changes, explicit confirmation, cancellation, rejected requests, finalized execution errors and successful receipt/state readback. Real full-consensus writes used Studio's built-in address, without exporting a key. The 17 finalized v2 receipts include successful deployment/writes and the intentional duplicate-evaluation error.

`docs/live-verification.json` records exact deployed-source equality, finalized receipts, validator votes, ten public bundle/source commitment checks and five valid stored audit packets. All 19 reviewed GitHub web files match the release source; all eight published assets match the built files byte-for-byte. Publication/version identifiers and hashes are in `docs/website-publication.json`, `docs/source-correspondence.json` and `docs/published-asset-checks.json`.

## Checks and retained disclosures

- Direct Mode: **57 passed**; GenVM lint: **3 checks passed**.
- Frontend: **14 passed**; TypeScript and production build passed.
- Code CI: https://github.com/ANZA24k/PolicyProof/actions/runs/39540287838 — successful for the reviewed v2 frontend/deployment commit.
- Repository: https://github.com/ANZA24k/PolicyProof

The app, repository and packets continue to state that commitments authenticate submitted bytes, not the truth or organizational origin of operational claims. Synthetic demonstrations remain clearly labeled. PASS is evidence-relative, not independently verified real-world compliance. Administrator-allocated capacity remains transparent and bounded; evaluations remain permissionless. The previous deployment and its evidence are retained separately as legacy provenance.
