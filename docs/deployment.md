# Protocol v2 deployment and verification

- Public website: https://policyproof.ansaf1st34.chatgpt.site
- Network: GenLayer Studionet, chain 61999
- RPC: https://studio.genlayer.com/api
- Current contract: https://explorer-studio.genlayer.com/address/0x910300ca08d112c7335691ED6C389746ca26Cf86
- Deployment: `0x69c5968639ffea949d95db6ff59ffee08bcdd1d233b5fb5d1751610d794a294c`
- Source commit: `875cb95b2509a46fb990620fe83aeae2f89a5260`
- Studio built-in account: `0x8c2abcd84c20090045ed1159b95a8ae8e0ef1551`

This is a fresh deployment, rather than a code upgrade of the legacy contract. `getContractCode` matches `contracts/policyproof.py` byte-for-byte. Normal (Full Consensus) was used. No private key was exported. Detailed receipts, validator votes, finalized records and historical audit packets are in `live-verification.json`; configured transaction links are in `web/src/deployment.json`.

## Verification scope

57 official Direct Mode tests cover permanent malformed UTF-8 bundle/source failures, repeated evaluation, owner-only recovery, independently grounded alternate quotes, packet forgery, source budgets and historical reconstruction across revisions after external source changes. 14 frontend tests cover offline packets, tampering, Unicode canonicalization, connection, network/account changes, confirmation gates, rejection, failed execution and successful readback. TypeScript and production builds also pass.

The published app's public browser review and clearly labeled simulated-provider checks are documented in `browser-verification.md`. The browser has no installed MetaMask/EIP-1193 provider. Actual MetaMask extension signing was therefore not performed and is not claimed. Real chain writes were exercised using Studio's built-in address. The simulated browser checks never send a real transaction.

The earlier deployment, transactions and cross-account verification are retained in `legacy-deployment.md` and `legacy-deployment.json`; they are historical provenance, not v2 execution evidence. All incident examples are synthetic. Cryptographic commitments prove submitted bytes, not their truth or organizational origin. Storage admission remains an administrator-allocated finite pilot.
