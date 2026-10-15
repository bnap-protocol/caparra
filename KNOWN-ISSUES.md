# Known issues

Everything below is open. The project is pre-alpha: none of it blocks
local testing, and all of it should be settled before Caparra handles
mainnet money. Each entry is ready to file as an issue.

Sources: the integration notes in [`notes/`](notes/) (the full text of
each finding, with file and line), [SECURITY-REVIEW.md](SECURITY-REVIEW.md),
and in the [bnap repository](https://github.com/bnap-protocol/bnap)
`spec/DECISIONS.md` and `spec/ERRATA.md`. To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Open LOW findings

IDs follow the notes they come from: `B5-` is the security review
(`notes/b5-security.md`), `N9a-` the HTTP carrier and gate
(`notes/n9a.md`), `N9b-` the MCP carrier (`notes/n9b.md`) and `N10-` the
client side (`notes/n10.md`). No HIGH or MEDIUM finding is open.

| ID | Crate | Description | Suggested fix |
| --- | --- | --- | --- |
| --- | --- | --- | --- |
| B5-A3 | bnap-carrier-mcp | When the scheme's OK settle fails (a sweep timed the outcome out during the action), `conclude` answers UNAVAILABLE without the FAILED settle and refund. The client gets its refund only by replaying after `pending_timeout` (`crates/bnap-carrier-mcp/src/gate.rs`). (notes/b5-security.md) | On an OK settle error, take `pending.charge(Status::Failed, 0)`, run the FAILED `settle_scheme`, then `outcome::settle`. |
| B5-A4 | bnap-carrier-mcp | `process` gets `offer.fields()` instead of `bnap_scheme_notes::admission_fields(..)`, so the notes 5.4 admission cutoff is not applied on MCP calls. It only matters with an offer lifetime above `pending_timeout + 120` (`crates/bnap-carrier-mcp/src/gate.rs`). (notes/b5-security.md) | Apply `admission_fields` for a notes pay entry, as `bnap-scheme-notes/tests/common/mod.rs` does. |
| B5-A5 | caparra-wallet | Notes held are wallet balance, not spending. `max_balance_per_origin` bounds them per origin, but nothing bounds the total held across origins, explicit `bnap fund` included (`pay.rs:643`). (notes/b5-security.md) | Add a global cap on notes held across origins. |
| B5-B1 | bnap-signer-file | `NotesKeyset::check` compares the unblinded signature `a*Y` with `==`, in variable time. The 33-byte compare sits next to an EC multiplication, so it is not practically measurable remotely (`keyset.rs:303`). (notes/b5-security.md) | Use `subtle::ConstantTimeEq`. |
| B5-B2 | bnap-core | `counter_key` concatenates `tu64(limit)`, `tu64(epoch)` and `tu64(now/epoch)` without length prefixes, so it is not injective. Collisions only merge operator-chosen counters (more restrictive). Already ERRATA N3a-10, implemented literally (`ids.rs:66`). (notes/b5-security.md) | Spec change: `lp(tu64(..))` or fixed-width integers. |
| B5-B3 | bnap-scheme-dpop | `StaticAuthority` keys bearer tokens in a `HashMap<String, _>`, so the final compare is variable time. SipHash keying makes probing impractical. (notes/b5-security.md) | Key by `sha256(token)`, or document the authority as test and development only. |
| B5-C2 | caparra-wallet | In `CommandSource::pay_invoice`, `read_to_end` of the child's stdout runs outside the 120 s timeout and is unbounded. A pay command that holds stdout open hangs `fetch_paid`, and the reservation stays counted (`paysource.rs:170`). (notes/b5-security.md) | One timeout over read and wait; cap stdout with `take(1 MiB)`. |
| B5-C3 | bnap-mcp | `--http` has no authentication: any local process that reaches the loopback port can spend within the caps. Browsers are stopped by the host check and preflight (`main.rs:85`). (notes/b5-security.md) | A random bearer token written to a 0600 file, or a 0600 Unix socket. |
| B5-C4 | several (bnap-scheme-dpop, caparra-wallet, bnap-signer-process) | Derived `Debug` prints bearer tokens, API tokens, credential headers and the note secret. Nothing logs them today. (notes/b5-security.md) | Hand-written redacting `Debug` impls. |
| B5-C5 | several (bnap-mcp, bnap-cli, bnap-scheme-l402, bnap-scheme-mpp, carriers, bnap-core, rails) | Secrets are not wiped from memory on drop: passphrases, bip39 without `zeroize`, macaroon and challenge keys, carrier MAC keys, the Schnorr `SigningKey`, the phoenixd password and webhook secret, the NWC URI. (notes/b5-security.md) | `Zeroizing` / `ZeroizeOnDrop`; enable `bip39/zeroize`. |
| B5-C6 | rails, bnap-mcp | Secret files (NWC, phoenixd, `bnap-mcp --passphrase-file`, LND macaroon path) are read without the mode check the signer key file gets. (notes/b5-security.md) | Reuse `bnap_signer_file::keyfile::read`, or warn. |
| B5-C7 | bnap-signer-file | The symlink check and the open are two lookups (no `O_NOFOLLOW`), and the file owner is not checked. Secrecy holds (mode read from the descriptor), but integrity against a writable directory does not (`keyfile.rs:120`). (notes/b5-security.md) | Open with `O_NOFOLLOW` and require the owner to be the process uid. |
| B5-C8 | bnap-rail-phoenixd | `PHOENIXD_URL` may be any `http://` URL, so basic auth can travel in clear text off the host (`lib.rs:310`). (notes/b5-security.md) | Require https unless the host is loopback. |
| B5-C9 | bnap-store-sqlite | The gate's use-store file and WAL get the umask mode. They hold receipts and kept answers, no key material. (notes/b5-security.md) | Create them 0600, as the wallet fix C1 does. |
| B5-C10 | caparra-wallet | If `Store::create` fails after the file is made (connect or KDF error), an empty `wallet.db` stays and a retry answers WalletExists. Found by the checker. (notes/b5-security.md) | Remove the file when create fails before the first commit. |
| N10-L1 | caparra-wallet | With NWC (no fee field in NIP-47) a payee's route hints can push a fee past the ceiling. It is recorded in full and blocks later payments, but the one payment overshoots. (notes/n10.md) | Check route-hint fees against the ceiling before paying. |
| N10-L2 | caparra-wallet, bnap-cli | A refused BNAP Lightning payment reads "Nothing was spent" followed by "N sat already went out over Lightning". After a pay source error on an L402 or MPP payment, `bnap resume` has nothing to collect (the reservation stays counted, the safe side). (notes/n10.md) | Fix the message wording; let `resume` check and collect or release L402 and MPP payments after a pay source error. |
| N10-L3 | caparra-wallet | A restore that recovered a pending operation's change and spent it, followed by a successful replay of that operation, writes the change notes back as unspent. The next spend of them is SPENT (counted at face value). No value lost, no cap bypassed. (notes/n10.md) | On replay, do not re-insert change notes already marked spent (check by `Y` before writing). |
| N10-L4 | caparra-wallet | Origin aliases (`https://host.` and `https://host`) get separate per-origin buckets. Daily and per-task caps still bound the total. (notes/n10.md) | Normalize origins (strip the trailing dot, lower-case the host) before bucketing. |
| N10-L5 | bnap-cli | `bnap paysource nwc <URI>` takes the secret on the command line (shell history, `ps`). `BNAP_NWC_URI` is the safer way and the help says the argument is optional. (notes/n10.md) | Drop the argument, or read it from stdin or a file and warn when given on argv. |
| N10-L6 | bnap-mcp | The per-task cap starts again with every `bnap-mcp` run unless `--task` names a group. Per-origin and daily caps (24 h rolling) still hold. (notes/n10.md) | Default `--task` to a persisted group, or document the restart reset clearly. |
| N9a-L2 | caparra-gate (bnap-carrier-http) | `check_ack` cannot bind the Response's `digest` or `offer_id` because the record holds neither. A socket-only process can get an ack for a real settled outcome under another credential's Digest. (notes/n9a.md) | Store `digest` and `offer_id` in the outcome record and compare them in `check_ack`. |
| N9a-L3 | caparra-gate (bnap-carrier-http) | When the OK settle fails and the FAILED fallback succeeds, the application's answer is still sent, with a FAILED refunded receipt. No client-triggered path was found. (notes/n9a.md) | Withhold the application body when the outcome settled FAILED; send only the receipt. |
| N9a-L5 | caparra-gate | The manifest is checked only at start. A gate running past `issued + max_age` keeps serving it and issuing offers. (notes/n9a.md) | Add a runtime check that stops offering (or reloads) once the manifest ages out. For now, restart with a new manifest. |
| N9a-L6 | caparra-gate (bnap-carrier-http) | On non-metered routes a buffered `text/event-stream` answer keeps an application `event: bnap-receipt`, while 10.2 says to strip it. (notes/n9a.md) | Strip application `bnap-receipt` events from buffered SSE answers. |
| N9a-L-d | caparra-gate | `HEAD` on a `GET` route is now refused rather than forwarded, but it is not priced either. (notes/n9a.md) | Price `HEAD` as the matching `GET` route, or document the refusal. |
| N9a-L-e | caparra-gate (bnap-carrier-http) | A native credential in `Authorization` has no size cap of its own. It is bounded only by the per-address verify limit and the server's header limits. (notes/n9a.md) | Apply an explicit size cap to native credentials before parsing. |
| N9a-L-f | caparra-gate (bnap-carrier-http) | `check_ack` accepts a Response without `unit` when the record has one. (notes/n9a.md) | Require `unit` in the Response whenever the record holds one. |
| N9a-L-i | caparra-gate | When every offer of a route is left out because a plug is unavailable (rail down), the answer is 429 RATE_LIMITED where 503 would be accurate. (notes/n9a.md) | Answer 503 UNAVAILABLE when offers are dropped for an unavailable plug. |
| N9a-L-j | caparra-gate | `loosely_matches` does not cover format suffixes such as `/v1/chat/completions.json`. Only some upstream frameworks route those. (notes/n9a.md) | Treat a trailing `.ext` format suffix as a loose match and refuse it like the other near misses. |
| N9a-L7 | caparra-gate | Once an address's mint limit is used up, a refusal owed a fresh offer on an exact route is 429 RATE_LIMITED, not 402 (DECISIONS row 24 against 8.2). The conformance run hits it unless `mints_per_minute` is raised. (notes/n9a.md) | Owner call on row 24 against 8.2; meanwhile document raising `mints_per_minute`, or reuse a cached offer where one exists. |
| N9b-L1 | bnap-carrier-mcp | A replay after the offer expired is STALE (the 4.4 check before `process`), so a missed receipt, or the refund of an outcome that timed out after a post-commit UNAVAILABLE, can be fetched only while the offer lives. This is open core erratum N3b-22. (notes/n9b.md) | Await the N3b-22 decision: on STALE, still call `process` for an authentic offer, or require offers to outlive `pending_timeout`. |
| N9b-L2 | bnap-carrier-mcp | Integers beyond the u64 range, or written with `.0`, pass the 2^53 rule: they are read as doubles, so `18446744073709551616` and `18446744073709551617` share a scope. The tool gets the canonical value, so the paid action is the one that runs. (notes/n9b.md) | Refuse integer literals above u64 (or above 2^53) in priced arguments, or document the double rule. |
| N9b-L3 | bnap-carrier-mcp | Free tools still see credential keys in `_meta`; they are stripped only for priced calls. (notes/n9b.md) | Strip credential keys from `_meta` for every call. |
| N9b-L4 | bnap-carrier-mcp | The denied-task list holds only the last 4096 IDs in memory. The client never learns a priced call's task ID, so no exploit path was found. (notes/n9b.md) | Refuse task-capable priced calls before commit. |
| N9b-L5 | bnap-carrier-mcp | No per-address limit on offer minting (DECISIONS row 24). A flood can evict a cached offer that an MPP-native payer still needs, who then gets BAD_OFFER after paying (refund `none`). Left to the deployment for now. (notes/n9b.md) | Add a per-address mint limit in the carrier, or pin offers that have an unpaid native challenge. |
| N9b-L6 | bnap-carrier-mcp | Payable refusals carry a fresh offer beyond the four codes 8.2 names (N9b-2). For SPENT a new payment cannot fix the original credential. (notes/n9b.md) | Send no fresh offer with SPENT (and review the other non-8.2 codes). |
| N9b-L7 | bnap-carrier-mcp | Non-credential `_meta` keys are outside the scope (like unlisted HTTP headers). Still open from round 1. (notes/n9b.md) | Say so in the MCP carrier note, or add listed `_meta` keys to the scope. |

Not a defect, recorded for completeness: receipts keep the full L402 or
MPP credential, which is a bearer token. Neither the CLI nor the MCP tool
prints it, and the wallet encrypts it at rest (`notes/n10.md`).

## Specification points that need an owner decision

### Errata candidates raised by the implementation

Caparra takes the literal draft-00 reading, or the safer one, until these
are decided. Details are in the named note.

| ID | Note | Short summary |
| --- | --- | --- |
| --- | --- | --- |
| N3b-1 | notes/n3-core.md | A credential with no pay is priced at `NO_PAY_BASE` (2^64 - 1) to stop a free-admission bypass; not the literal reading. |
| N3b-15 | notes/n3-core.md | Value counted is `min(scheme claim, backing)`, not the scheme's claim; section 7 wording. |
| N3b-16 | notes/n3-core.md | Confirm that schemes MUST make the refund a superset of the change (one running total per `ReplayKey`). |
| N3b-22 | notes/n3-core.md | Replays of expired offers: gate calls `process` on STALE for an authentic offer, or offers must outlive `pending_timeout`. |
| N3b-23 | notes/n3-core.md | Reword sections 3 and 6.4 so replay detection precedes pricing. |
| N3b-28 | notes/n3-core.md | Overview's `verify_unblinded` signature must take the secret, not `Y`. |
| N3b-29 | notes/n3-core.md | The change ledger belongs to the use store, not the signer alone. |
| N6-1 | notes/n6.md | Late OK settle then timeout refunds less than the value; options: second ladder, skip the OK settle after the timeout, or accept the loss. |
| N8-3 | notes/n8-attestations.md | Replays whose attestation no longer verifies miss their outcome; key the lookup on claimed IDs, or verify at commit time. |
| (N11 run) | notes/n9a.md | Pick one reading of "the artifact's bytes" (4.1) for L402 and MPP native entries. |

### Provisional decisions (bnap `spec/DECISIONS.md`)

Each row answers an ERRATA row marked "owner decision needed". Caparra
implements the provisional choice.

| Row | Decision | Provisional choice |
| --- | --- | --- |
| --- | --- | --- |
| 13 | Metered route in the manifest | Manifest carries the price ceiling only; the per-unit rate travels in the offer's pay entry parameters. No new manifest member. |
| 21 | Timeout defaults | `pending_timeout` defaults to 300 s and `replay_window` to 86,400 s when the manifest omits them. |
| 22 | ES256 co-signature | Not in v0.5. No record type assigned; BIP-340 stays the only receipt signature. Revisit with an HSM signer. |
| 23 | GREASE for scheme IDs and carrier names | Not in v0.5. Odd GREASE TLV types stay mandatory-to-ignore and servers keep sending one. |
| 24 | Native challenge minting | Treated as MUST: at most one invoice per offer nonce, plus a per-address mint rate limit. |
| 25 | Class None value schemes | Added to section 7: admissible only at price 0, never with a waive or discount effect. |
| 30 | Credential size on HTTP | HTTP carrier caps a Credential at 9,216 bytes (12,288 base64url characters); larger is TOO_LARGE. |
| 31 | bnap:notes vs draft-00 | Notes scheme rewritten in draft-00 terms (`spec/schemes/bnap-notes-draft-00.md`); body encoding is TLV. |

### Errata rows that need a decision (bnap `spec/ERRATA.md`)

| Row | Summary | Status |
| --- | --- | --- |
| 13 | Manifest `price` on a metered route is the ceiling (per the vector); whether the manifest should also carry the rate is open. | Owner decision needed (provisional in DECISIONS) |
| 21 | Draft-00 gives no defaults for `replay_window` and `pending_timeout`; choose 300 s and 86,400 s or make both required. | Owner decision needed (provisional in DECISIONS) |
| 22 | Overview allows an ES256 co-signature, but draft-00 assigns no record type for it. | Owner decision needed (provisional in DECISIONS) |
| 23 | Overview reserves GREASE scheme IDs and carrier names; draft-00 defines none. Keep or drop. | Owner decision needed (provisional in DECISIONS) |
| 24 | Draft-00 says SHOULD mint at most once per offer nonce; overview says MUST. Draft-00 weakens a MUST with no reason given. | Owner decision needed (provisional in DECISIONS) |
| 25 | Draft-00 does not limit class None value schemes to price 0; adding the overview rule is a normative change. | Owner decision needed (provisional in DECISIONS) |
| 30 | Credential may be 16,384 bytes but the HTTP field minimum is 12,288 characters (9,216 bytes). Raise the minimum or cap on HTTP. | Owner decision needed (provisional in DECISIONS) |
| 31 | bnap:notes tab is still the v0.4 profile; needs a draft-00 rewrite and a body encoding choice (TLV or CBOR). | Owner decision needed (provisional in DECISIONS) |
