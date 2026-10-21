# PolicyProof architecture

PolicyProof is an evidence-review primitive for operational rules, demonstrated through a synthetic incident-response standard. It does not handle money, settle rewards, or certify actual organizational behavior.

## State and lifecycle

An admitted organization calls `create_policy(id, policy_json)` to lock a name, scope and 1–6 uniquely identified natural-language requirements. The canonical JSON SHA-256 is stored with the creator. There is no update or delete method.

An admitted participant calls `submit_assessment(policy_id, assessment_id, subject, period, url, sha256)`. Participants can submit against another organization's policy. ID, subject, period and policy binding cannot change. Submission commits evidence; it does not evaluate it.

Anyone can call `evaluate(id)`. A leader independently retrieves the bundle and all 1–3 source files, verifies exact SHA-256 bytes, validates subject/period/policy binding, and asks an LLM to assess each criterion. Validators run this entire process again. They compare the complete normalized result including all criterion states, integrity errors, synthetic flag and bundle hash. They do not accept a leader's verdict merely because it has a valid shape. A disagreement can lead to rotation or an undetermined transaction; it never becomes an application PASS automatically.

Every determinate semantic finding carries a zero-based source index and up to three newline-separated exact supporting excerpts, in document order. The accepted leader's quotes are retained with a bounded `policyproof/audit-v2` packet containing the original policy, bundle text, source snapshots and all content commitments. The packet itself is committed with SHA-256. UNKNOWN carries source -1 and an empty quote.

Validators independently retrieve and assess the exact inputs, verify both their own and the proposed packets, and require identical criterion states, derived verdict, synthetic flag and immutable input snapshots. Valid grounded quotations may differ. They do not reach consensus on identical prose. Quote matching alone is not substantive validation: independent model re-execution supplies that check. A deterministic verification runs again before finalized storage.

Historical reconstruction needs only finalized state or a downloaded audit JSON: recompute packet and policy hashes, hash the preserved bundle and source UTF-8 bytes, check historical bindings and source indices, verify each quotation verbatim, then derive the verdict. External source availability or subsequent branch/file changes do not affect those preserved snapshots. Earlier revisions remain auditable after new evidence commitments.

The overall verdict is deterministic: any VIOLATED criterion yields FAIL; otherwise any UNKNOWN yields INCONCLUSIVE; otherwise all criteria SATISFIED yields PASS. A demonstrated violation can fail a policy even when a different criterion is unknown.

The submitter can commit up to three distinct evidence revisions. A revision must follow evaluation of the preceding revision and cannot reuse an earlier bundle hash. Prior review entries remain intact. The website treats an unevaluated revision as PENDING and never labels it with an earlier revision's verdict.

## Retrieval, resource and model boundaries

Only HTTPS raw.githubusercontent.com files pinned to a full 40-character Git commit are accepted. URL credentials, ports, query strings, escapes, branch names, empty/dot path segments and other hosts are excluded. File types are JSON, Markdown or text. The expected exact content hash rejects redirected or changed content. One bundle plus three documents, each at most 16,000 bytes, and a combined 24,000-byte source budget bound retrieval and model input. Canonical ASCII audit packets are capped at 260,000 bytes per review; storage has at most three packets per assessment. Hash verification happens before model evaluation. Sources are not recursively followed; links in source text are inert data.

All JSON parsers reject duplicate keys and non-finite constants. Policy and bundle schemas reject unknown fields. LLM output must identify each criterion exactly once, use one of three allowed states, and satisfy source-quote checks. Missing/ambiguous records become UNKNOWN. Explicit contradictory records can become VIOLATED. The prompt separates policy rules from output authority and treats source instructions as untrusted data. Independent validators reduce prompt-injection risk; no LLM system guarantees immunity.

HTTP 429/5xx, unexpected retrieval failures and malformed/model failures revert evaluation after consensus without recording a review or consuming a revision. Retry the same committed evidence. Verified hash mismatches, fixed HTTP failures, oversized documents invalid UTF-8 after successful hash verification, excessive combined source bytes, excessive packet size, and invalid bundle structure record INCONCLUSIVE with an explicit integrity code. These are permanent evidence failures; recording the review allows the owner to commit corrected evidence as the next revision. Re-evaluation of the same reviewed revision reverts.

## Pilot capacity

Storage admission is explicit. The deployer has four reserved policy slots and eight assessment slots. The administrator may allocate account quotas, bounded by 128 reserved policies and 128 assessments across at most 32 admitted accounts. Used slots cannot be reclaimed or reassigned. A new account cannot exhaust another account's reservation. Evaluation is permissionless. Admission is a resource limit, not an endorsement, identity assertion or power to alter findings. This bounded Studionet pilot is not an unlimited production registry.

## Website and wallet

The public Vite frontend uses genlayer-js 1.1.8 and Studionet chain 61999. It reads LATEST_FINAL state and performs browser-side bundle and source hash checks on request, plus offline historical packet validation and JSON export. On a new revision it shows PENDING until that revision has its own review. Untrusted text is HTML escaped and source links use the same immutable-host restrictions.

Connecting a browser wallet calls eth_requestAccounts only. No automatic signature, transaction, token approval, chain switch, private-key import or spending permission occurs. A separate review dialog displays the exact contract, account, method and arguments before signing. A write sends zero token value. Completion requires a finalized receipt, GenVM SUCCESS, full MAJORITY_AGREE consensus, and matching finalized state readback. Wallet rejection and unsuccessful execution remain errors.

Studio's built-in account is used only inside Studio for the pilot deployment and demonstration. It is never embedded in the website or exported. A visitor uses their own MetaMask-compatible provider to sign website writes. Read access requires no wallet.

## Limits

Evidence provenance is a public Git commitment, not real-world authenticity. Organizations can publish fabricated records. The policy author chooses the criteria and scope. Findings are evidence-relative and can be wrong or fail to reach consensus. No reward escrow, hidden server-side verdict, legal assurance, identity check or real-time monitoring is claimed. Studionet can reset. Synthetic examples are labeled in each document and stored result.
