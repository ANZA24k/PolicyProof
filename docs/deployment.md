# Studionet deployment and verification

- Network: stable GenLayer Studionet (61999)
- RPC: https://studio.genlayer.com/api
- Current address: `0x37b36cBdB694c3B76Bf7F482917d5e774c4CF409`
- Explorer: https://explorer-studio.genlayer.com/address/0x37b36cBdB694c3B76Bf7F482917d5e774c4CF409
- Built-in Studio deployer: `0x9e344d9103d51063eff1291628c156dc62b703b4`
- Original deployment: `0x581791e7d7c47cdd35b37802f7a8bbc120a5761fe18d7a57e46de22a9ed3e3ae`
- Current-source installation (bounded consensus diagnostics added): `0xcdb119f71c07d37624a15e657d7b8421db1f23809ff7f9c7e912d763577b7e12`
- Current source snapshot: `9fd06882f9451046dd6e71fd91b4094776da76d6`.
- Initial excerpt fix commit: `38b473adc85259cd7f4516aee03ffa82fb95001e`; the final repository source also includes bounded mismatch diagnostics, matching the current RPC code.

The contract was deployed using Studio's existing built-in account in **Normal (Full Consensus)** mode. No private key was exported. Live checks compare `getContractCode` byte-for-byte to the repository and require GenVM SUCCESS, MAJORITY_AGREE, and finalized state for successful actions.

## Compatibility issue found and fixed

The original implementation required each model quote to be one contiguous source substring. A model cited detection and notice lines together while omitting an intervening acknowledgement line. The quote failed grounding and the application reverted with a temporary failure. No verdict or revision was consumed.

Diagnostic output identified the issue. The final source verifies up to three newline-separated verbatim excerpts in source order. It still rejects invented text, rearrangement and ellipses. Four regression tests cover this behavior. The temporary full-model-response logging was removed. The final source retains bounded diagnostics of validation errors and normalized decision mismatches; it does not log arbitrary model responses. The PASS and INCONCLUSIVE evaluations used the excerpt-corrected logic; the subsequent diagnostic update changes logging only. The cross-account FAIL evaluation used the current source. The original deployment transaction alone is not evidence of the final code version.

Initial retryable evaluation failures (kept as transparent provenance):

- `0x28ce61429bc1946ffe7ba60fc2412eee9a77523112e0f393f5139bf82361aea3` — INC-42, original quote handling.
- `0x918939415968134d019d7e73d3f8bae6a02543e3cfe18adaa2a67e72d1043ad6` — INC-43, original quote handling.
- `0x5e358cfda6107ff7ed1885ecd4bfbba632b8cb751973a3ea511efc791ff44768` — diagnostic reproduction.
- `0x6968a1587f9fe3eb421dad5d15fc16d6819920e1619c5d519e6c0cdc5fc0de58` — temporary diagnostic installation.

These failures are not reported as successful evaluations. `scripts/check-live.mjs` checks successful receipt entries separately from expected failures.

## Verification scope

- Contract tests: official GenLayer Direct Mode, including independent validator reruns, changed sources, malformed models, access control and history boundaries.
- Frontend tests: EIP-1193 mock provider confirms connection calls only eth_requestAccounts; no signing, chain switch or transaction on connection. Failed execution cannot be shown as a successful write.
- Studio: real deployment and full-consensus evaluation using the existing built-in account.
- Live reads: latest finalized policies, assessments, hashes and outcomes.
- Browser visual QA was unavailable because this environment did not expose the Sites control-browser capability. Production build, type checks and provider-safety tests were completed.
- Real MetaMask extension signing was not available. Studio signing and provider-level tests cover the available routes; no real MetaMask end-to-end claim is made.
- Creating an extra Studio account was initially rejected by automatic approval review. After resuming, an existing built-in Studio account (`0xe74b0c822c1af78046ca0304b2aa69160c6cc3b8`) was available. Importing the deployed contract and evaluating INC-43 from this account succeeded under full consensus, demonstrating permissionless cross-account evaluation without creating another account. Cross-account submissions and owner-only revision checks are also covered in Direct Mode.

## Verified results

| Assessment | Final outcome | Key findings |
| --- | --- | --- |
| INC-42 | PASS | ACK, NOTICE and REVIEW satisfied. |
| INC-43 | FAIL | ACK and NOTICE violated; REVIEW satisfied. |
| INC-44 | INCONCLUSIVE | ACK and REVIEW satisfied; NOTICE unknown. |

INC-43 initially reached MAJORITY_DISAGREE and stored no result. A later evaluation reached MAJORITY_AGREE with successful GenVM execution. One validator independently disagreed on the REVIEW criterion while the accepting quorum agreed with the leader. This demonstrates substantive independent comparison; the contract does not claim unanimity or guaranteed first-attempt consensus. All receipts and vote maps are in live-verification.json.

The Explorer Code tab may display original deployment code after Studio development upgrades. The reproducible read-only release check uses `getContractCode` from the current RPC and verifies exact bytes, rather than assuming the Explorer's original source panel is current.
