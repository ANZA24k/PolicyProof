# Public browser verification — protocol v2

Verified 2026-10-21 in the available Chrome browser against the published site. No sign-in wall was shown. Sites reports audience `public`; publication version 2 is recorded in `website-publication.json`.

## Real public frontend

- Opened https://policyproof.ansaf1st34.chatgpt.site/#workspace. Finalized state displayed one policy, four assessments and seven historical reviews: INC-42 PASS, INC-43 FAIL, INC-44 INCONCLUSIVE, invalid-source PASS after recovery.
- Clicked **Verify public bytes** on INC-42 revision three: “Bundle and 1 source document(s): exact SHA-256 verified.”
- Expanded INC-42 history: revision one preserves `INVALID_UTF8`; revisions two and three show separate PASS packets, content commitments and retained source indices/quotations.
- Clicked **Verify stored audit packet** for revisions two and three. Both reported successful packet/bundle/source-hash and three criterion-citation validation, with no source network request needed.
- Downloaded revision two audit JSON through the browser. The exact download is preserved as `audit-example-revision-2.json` and independently verified with `web/src/audit.mjs` in Node, without network access.
- Clicked **Connect wallet**: the browser reported “Install MetaMask or an EIP-1193 browser wallet to write. Reading needs no wallet.” No provider was installed, so real MetaMask connection/signing could not be performed and is not claimed.
- Desktop visual QA inspected the public workspace, historical citations, confirmation dialog and wallet result page. Mobile viewport/device QA was not performed.

## Browser wallet simulation — explicitly not real chain execution

Open https://policyproof.ansaf1st34.chatgpt.site/wallet-check (the `.html` link redirects here). This page is visibly labeled **SIMULATED EIP-1193 PROVIDER** and sends zero real transactions. It imports the same production `connectWallet` and `sendReviewedWrite` functions; it does not inject a provider into the public app.

1. Click **Connect simulated wallet**; it returns the test account.
2. Click **Test missing confirmation**: rejected with zero simulated write attempts.
3. Click **Review simulated transaction**: inspect account, method, arguments, zero value and chain 61999. **Cancel** closes the dialog without any write attempt.
4. Select each scenario and repeat Review → Confirm:

| Scenario | Observed result |
| --- | --- |
| Wrong network | Explicit Studionet chain/RPC instruction; zero simulated writes. |
| Wallet rejection (4001) | “Wallet request rejected. No completion is confirmed.” |
| Finalized execution failure | “Execution success and full consensus could not be confirmed.” |
| Account changes before signing | “Account changed. Reconnect and review.”; zero simulated writes. |
| Successful receipt and state readback | Simulated finality, full consensus and matching review readback verified. |

These checks establish browser UI and shared wallet-code behavior, not MetaMask extension behavior. Real chain execution used Studio's existing built-in account in Normal (Full Consensus) mode. `live-verification.json` verifies 17 FINALIZED receipts, including successful v2 writes and a deliberately failed repeated evaluation (`Revision already reviewed`).

## Source and screenshots

All 19 GitHub web files match the local source used for the Sites build by Git blob hash (`source-correspondence.json`). All eight public build assets match that release build byte-for-byte (`published-asset-checks.json`). The exact Sites source commit and GitHub source commit are recorded in `website-publication.json`.

Screenshots in `browser-evidence/`:

- `policyproof-v2-workspace-browser.jpg`: real finalized public records and criterion results.
- `policyproof-v2-audit-browser.jpg`: retained citations and offline audit verification.
- `policyproof-v2-wallet-confirmation.jpg`: explicitly simulated confirmation dialog.
- `policyproof-v2-wallet-results.jpg`: explicitly simulated successful readback.
- `policyproof-v2-studio-recovery.jpg`: real FINALIZED/SUCCESS Studio recovery execution and validator agreement.

Cryptographic commitments establish submitted-byte integrity, not truth or organizational origin. All demonstration incident claims are synthetic. The administrator allocates finite creation capacity; evaluation remains permissionless.
