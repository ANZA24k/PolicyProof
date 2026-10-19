# GenLayer Project submission

## Project name
PolicyProof

## One-liner
Lock operational policies, commit public evidence, and verify each criterion through independent GenLayer consensus.

## Description
PolicyProof verifies public operational evidence against locked policies. Organizations define a scope and up to six requirements; participants commit a subject, reporting period and immutable evidence bundle with SHA-256 hashes. GenLayer leaders and validators independently retrieve the exact bundle and source documents and assess every criterion. Deterministic rules derive PASS, FAIL or INCONCLUSIVE. Submitters may append up to three evidence revisions while earlier reviews remain visible. Temporary retrieval/model failures can be retried without consuming a revision. The website reads finalized contract state, verifies public source hashes and supports explicit MetaMask-compatible writes. Connection alone never signs or transacts. The Studionet incident-response pilot uses labeled synthetic documents; outcomes assess the evidence, not real-world compliance. No rewards or escrow are used.

## Evidence

- Repository: https://github.com/ANZA24k/PolicyProof
- Current contract: https://explorer-studio.genlayer.com/address/0x37b36cBdB694c3B76Bf7F482917d5e774c4CF409
- Source: https://github.com/ANZA24k/PolicyProof/blob/main/contracts/policyproof.py
- Live verification: https://github.com/ANZA24k/PolicyProof/blob/main/docs/live-verification.json
- Deployment provenance: https://github.com/ANZA24k/PolicyProof/blob/main/docs/deployment.md
- CI: https://github.com/ANZA24k/PolicyProof/actions
- Website: https://policyproof.ansaf1st34.chatgpt.site — initial owner-private publication; make public before submitting it for external review.

Submission category: **Projects**, because the application includes a real contract and integrated website. Do not submit as a standalone Intelligent Contract.

## Before submission

The website needs public audience access for stewards. Initial creation preserves the Sites default owner-private audience. No review, ranking, acceptance or points are promised.

The deployed contract is a bounded pilot with admitted storage slots; evaluation is permissionless. Direct Mode covers cross-account authorization; an existing separate Studio account successfully evaluated INC-43 on-chain. Real MetaMask extension signing and browser visual QA were unavailable; see deployment.md for exact verification scope.
