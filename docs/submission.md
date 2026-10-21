# GenLayer Project submission

## Project name
PolicyProof

## One-liner
Lock operational policies, commit public evidence, and verify each criterion through independent GenLayer consensus.

## Description
PolicyProof verifies public operational evidence against locked policies. Organizations define a scope and up to six requirements; participants commit a subject, reporting period and immutable evidence bundle with SHA-256 hashes. GenLayer leaders and validators independently retrieve the exact bundle and source documents and assess every criterion. Deterministic rules derive PASS, FAIL or INCONCLUSIVE. Submitters may append up to three evidence revisions while earlier reviews remain visible. Temporary retrieval/model failures can be retried without consuming a revision. The website reads finalized contract state, verifies public source hashes and supports explicit MetaMask-compatible writes. Connection alone never signs or transacts. The Studionet incident-response pilot uses labeled synthetic documents; outcomes assess the evidence, not real-world compliance. No rewards or escrow are used.

## Evidence

- Repository: https://github.com/ANZA24k/PolicyProof
- Current contract: https://explorer-studio.genlayer.com/address/0x910300ca08d112c7335691ED6C389746ca26Cf86
- Source: https://github.com/ANZA24k/PolicyProof/blob/main/contracts/policyproof.py
- Live verification: https://github.com/ANZA24k/PolicyProof/blob/main/docs/live-verification.json
- Deployment provenance: https://github.com/ANZA24k/PolicyProof/blob/main/docs/deployment.md
- CI: https://github.com/ANZA24k/PolicyProof/actions
- Website: https://policyproof.ansaf1st34.chatgpt.site — public access enabled.

Submission category: **Projects**, because the application includes a real contract and integrated website. Do not submit as a standalone Intelligent Contract.

## Review path

1. Open the public website and select INC-42, INC-43 and INC-44. Confirm PASS, FAIL and INCONCLUSIVE from finalized state.
2. Click **Verify public bytes** to hash the commit-pinned bundle and source documents.
3. Open **Revision history** for INC-42: revision one records `INVALID_UTF8`; revisions two and three retain separate successful evidence packets and different source commitments.
4. Open **Stored audit packet** for each successful revision; click **Verify stored audit packet**. The packet, policy, bundle and source hashes and criterion quotations verify without an external fetch. Download audit JSON for independent reconstruction.
5. Inspect `invalid-source` for permanent source-encoding failure and controlled correction.
6. Browser wallet checks at `/wallet-check.html` explicitly simulate network/account changes, confirmation, rejection, failed execution and successful readback using production wallet code. The app's Connect wallet uses a real browser provider when installed. No MetaMask extension was available in the verification browser; actual MetaMask execution is not claimed. Real writes used Studio's built-in address.

See `steward-response.md`, `browser-verification.md`, `deployment.md`, and the machine-readable verification/publication records. Creation requires allocated pilot capacity; evaluation is permissionless. Cryptographic commitments authenticate submitted bytes, not truth or organizational origin. All demonstrations are synthetic.
