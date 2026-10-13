# Integration notes: N3, `bnap-core` and `bnap-plug`

Two parts, one branch. Part A (the encoding layer) was built on
`node/n3a`. Part B (socket semantics and the plug traits) continues on
`node/n3-core`, which starts at `node/n3a`'s last commit `cc24e55`, so
`node/n3-core` holds both parts and supersedes `node/n3a` for merging.
Part B is documented at the end of this file, from "Part B" on.

## Part A: `bnap-core` encoding and cryptography

Branch `node/n3a`, crate `crates/bnap-core` only. Normative source:
`bnap/spec/socket-draft-00.md` (doc rev 39), with `spec/ERRATA.md` and
`spec/DECISIONS.md`. Vectors: `bnap/vectors/vectors.json` at bnap commit
`14bbd5e`, copied to `crates/bnap-core/tests/data/vectors.json`.

### Public API

Everything is I/O-free and RNG-free. Callers pass the clock (`now`, Unix
seconds), nonces, BIP-340 auxiliary randomness and GREASE randomness in.

| Module | What it exposes |
| --- | --- |
| `encoding` | `bigsize`, `write_bigsize`, `read_bigsize` (minimal enforced), `bigsize_len`, `tu64`, `read_tu64` (minimal enforced, at most 8 bytes), `lp`, `write_lp`, `read_lp` |
| `tlv` | `TlvStream` (`push`, `insert`, `from_records`, `get`, `to_bytes`, `signed_bytes(exclude)`, `parse(bytes, StreamKind)`), `StreamKind::{TopLevel, Nested}`, `TypeRange::of`, `is_signature_type`, `is_grease_type`, `grease_type(seed)`, `nested_type_allowed`, `entry_list`, `parse_entry_list`, `Fields` (even/odd rule helper), `write_record` |
| `hash` | `sha256`, `tagged_hash`, `TaggedHasher`, `hmac_sha256`, `hmac_sha256_verify` (constant time), `tags::*` (every socket tag), 32-byte newtypes `OfferId`, `Scope`, `Context`, `Digest`, `UseId`, `RailId`, `ReplayKey`, `CounterKey` |
| `schnorr` | `Key` (x-only, 32 bytes, hex serde), `Signature` (64 bytes, hex serde), `SigningKey` (`from_secret_bytes`, `public_key`, `sign(msg32, aux32)`), `Key::verify(msg32, sig)`, `SchnorrError` |
| `offer` | `OfferFields` (builder input and parser output; `offer_id()`, `sign(key, Some(&k_mac), aux)`, `sign_with_limit`, `check_binding_classes`), `Offer` (`parse`, `parse_with_limit`, `bytes`, `fields`, `offer_id`, `offer_sig`, `mac`, `signed_bytes` = S, `sig_message`, `verify_signature`, `verify_mac`, `check_authenticity`, `check_expiry`, `check_scope`, `check_offered`, `check_binding_classes`, `check_client`), `PayEntry`, `AttestEntry`, `NativeEntry`, `Effect`, `GateOfferCheck` (`check_bytes`, `check`), `ClientOfferCheck`, `same_origin`, record-type constants in `types`, `pay_types`, `attest_types`, `native_types` |
| `credential` | `Credential` (`new`, `to_bytes`, `parse`, `parse_with(CredentialParse)`, `context`, `digest`, `replay_key`, `check_binding_classes`, `check_tls_binding`, `sort_attest`, `pay_scheme`, `attest_schemes`), `OfferRef::{Inline, Id}`, `SchemePart` (scheme, body, witness), `CredentialParse` (size limit, known ext types), free `context`, `digest`, `native_context`, `native_digest`, and `GateOfferCheck::check_credential(cred, cache)` / `check_native(offer, scheme)` |
| `ids` | `use_id`, `rail_id`, `replay_key`, `rate_key`, `quota_key`, `rail::{LN, ONCHAIN, EVM, CARD, ln, onchain, evm, card}` |
| `http` | `action_scope(method, target, content, headers)`, `route_scope(origin, route_id)`, `target(manifest_origin, request_target)`, `HTTP_MAX_CREDENTIAL` (9,216, DECISIONS row 30) |
| `response` | `ResponseFields` (`sign`, `sign_with_limit`), `Response` (`parse`, `parse_with_limit`, `fields`, `ack`, `ack_message`, `verify_ack`, `answers`, `check_required`, `check_client`), `Status`, `ReceiptError` |
| `error` | `ErrorCode` (16 codes; `code`, `name`, `http_status`, `sends_fresh_offer`, `has_retry_after`, `from_code`, `from_name`, `FromStr`, `TryFrom<u64>`), `ErrorObject` (8.2 TLV; `new`, `with_detail`, `to_bytes`, `parse`, `socket_code`), `Error` (typed check failure; `code()` maps to `ErrorCode`), `MalformedKind`, `BadOffer`, `Stale`, `Object` |
| `manifest` | `Manifest`, `ManifestKey`, `KeyUse`, `ManifestLimits`, `Route` (`matches`), `RouteAttest`, `RouteScopeMode`, `jcs`, `Manifest::{jcs, sig_message, sign}`, `SignedManifest` (`parse`, `verify`, `manifest`, `sig`, `hash`, `jcs`), `Pin`, `accept(pin, origin, bytes, now)` (the 9.3 fetch rule), `ManifestError` |
| `class` | `BindingClass::{S, A, O, None}` with `FromStr` (`S`, `A`, `O`, `none`) |
| `limits` | `Limits` (`Default`, `from_manifest`), `MAX_OFFER`, `MAX_CREDENTIAL`, `MAX_RESPONSE`, `CLOCK_SKEW`, `DEFAULT_PENDING_TIMEOUT` (300), `DEFAULT_REPLAY_WINDOW` (86,400), `expired`, `in_future` |

`bnap_core::secp256k1` re-exports the `bitcoin` crate's secp256k1; no second
secp256k1 is added.

#### How a gate uses it (4.4 order)

1. `Credential::parse_with(bytes, &CredentialParse { max_credential, known_ext_types })`:
   TOO_LARGE, MALFORMED, VERSION for the credential.
2. `GateOfferCheck { now, max_offer, mac_keys, offer_keys, action_scope, route_scope }
   .check_credential(&cred, |id| cache.get(id))`: offer size, parse and
   version, authenticity (MAC, or held key + `issued_at` + `offer_sig`),
   expiry (with the chosen pay entry's `quote_expires`), scope, offered
   schemes. Returns the `Offer`.
3. `cred.check_binding_classes(registry_lookup)` and
   `cred.check_tls_binding(exporter)`.
4. `ctx = cred.context(&offer.offer_id(), &action_scope)`,
   `digest = cred.digest(&ctx)`; give both to the scheme read-only.
5. `ids::use_id(scheme, local)` for every local ID the scheme returns,
   `ids::rail_id(kind, canonical)` for the rail's canonical bytes,
   `cred.replay_key(&ctx, &all_ids)`.
6. Build the receipt with `ResponseFields { .. }.sign(&receipt_key, &aux)`.

Every check returns `bnap_core::Error`; `err.code()` is the draft-00 code and
`ErrorObject::from(&err)` builds the 8.2 Error object.

### Decisions made

- **Builders validate by parsing.** `OfferFields::sign` and
  `ResponseFields::sign` serialize, sign, then run the parser on the result,
  so a built object always passes the parser. `Credential::to_bytes` runs
  the same rules as `Credential::parse`.
- **Received bytes are kept.** `Offer` and `Response` keep the bytes as
  received; OfferID, `S`, the MAC input and the ack input are computed from
  the received records, unknown odd records included.
- **`S` is every record outside 240 to 1000**, so records above 1,000 (GREASE
  included) are under `offer_sig`, the MAC and the ack, as draft-00 4.2 and
  8.1 say and the vectors prove (ERRATA row 7). "Below the signature range"
  is the v0.5 wording and is not what the build does.
- **Version is checked first.** Parsers read `version` right after framing;
  a version other than 1 is VERSION before any other record rule runs.
- **K_mac is 32 bytes** (`[u8; 32]`), as in the vectors. Draft-00 does not
  fix its length.
- **Credential unknown odd records** are kept in `Credential::unknown` so a
  sender can add GREASE, and they enter no hash. Unknown odd records inside
  `pay` and `attest` parts are dropped.
- **Binding classes come from the caller.** Checks that need the registry
  take `Fn(&str) -> Option<BindingClass>`; an unknown scheme counts as
  class None (and so is never class S).
- **DECISIONS row 25** is enforced in `check_binding_classes`: a class None
  pay entry with amount above 0 is refused, as is a class None attestation
  that waives, discounts or carries a quota.
- **DECISIONS row 21** defaults are in `Limits::default()`; row 30 is
  `http::HTTP_MAX_CREDENTIAL` (the carrier applies it).
- **Manifest signature over the received value.** `SignedManifest::verify`
  checks `sig` over JCS of the document as received minus `sig`, so unknown
  members are covered. `Manifest::sign` serves JCS of the manifest with
  `sig` added.
- **Effect** serializes in the manifest as `required`, `waive`,
  `discount`, `quota` (ERRATA row 12).

### ERRATA list (ambiguities found, literal draft-00 reading taken)

| # | Where | Ambiguity | What `bnap-core` does |
| --- | --- | --- | --- |
| N3a-1 | 2, type ranges | Nested streams "use only 0 to 239, the experimental range and GREASE", but nothing says how a receiver treats another type | MALFORMED (`TypeNotAllowed`) in every nested stream: pay, attest and native entries, credential parts, `ext` |
| N3a-2 | 4.1 vs 4.4 | `issued_at` is "Required when `mac` is absent" (a record rule, so MALFORMED?), but 4.4 step 3 lists it under authenticity (BAD\_OFFER) | The parser accepts it; `check_authenticity` returns BAD\_OFFER (`MissingIssuedAt`); the builder refuses to sign such an offer |
| N3a-3 | 4.3, 12 | A route-scope offer "carries no native record", with no error code | MALFORMED at parse |
| N3a-4 | 4.1 | `value` and `epoch` on attest effects that do not use them (required, waive); `rate` in a non-metered offer | Accepted and ignored |
| N3a-5 | 4.1, 5.1 | Empty scheme IDs and units are not forbidden, but an empty pay scheme ID is indistinguishable from "no pay" in the Context (`lp(empty)`) | MALFORMED for an empty scheme ID (offer entries and credential parts) and an empty unit |
| N3a-6 | 2, "empty" row | "An absent record and a present record with an empty value ... MUST mean the same" is stated for formula inputs; its reach is unclear | Applied to credential `binding`, `ext`, part `body` and `witness`, every entry list, and the offer `headers` record. Required fixed-length records still need their length |
| N3a-7 | 10.1 | "content hash ... or empty when there is no content": is zero-length content "no content"? | Zero-length content hashes as empty, as `bnap_ref.py` does (`H(content) if content else b""`). The literal alternative, `H("")`, gives a different scope |
| N3a-8 | 4.1, 10.1 | `headers` is "comma-separated lower-case field names"; spaces and upper case are not addressed | The record must be RFC 9110 tokens without upper case, joined by bare commas, or the offer is MALFORMED; `http::action_scope` lower-cases names before hashing |
| N3a-9 | 6.1 | ReplayKey ids are "sorted bytewise"; duplicates (one payment reported twice) are not addressed | Sorted, not deduplicated, as the reference does |
| N3a-10 | 6.2 | `tu64(k) ‖ tu64(epoch) ‖ tu64(⌊now / epoch⌋)` has no length prefixes, so different (k, epoch) pairs can give the same bytes (k = 0x0102, epoch = 0x03 against k = 0x01, epoch = 0x0203) | Implemented literally in `ids::rate_key` and `ids::quota_key`. A later draft could use `lp(tu64(…))` or fixed-width integers |
| N3a-11 | 2, sizes | "Unless the manifest's limits raise them": may a manifest lower a limit? | `Limits::from_manifest` takes the larger of the default and the manifest value |
| N3a-12 | 2 vs 9.3 | 9.3 writes `not_after >= now` for offer keys; section 2 allows 60 s skew "on every expiry check" | The offer key check allows 60 s of skew. The receipt key check is `not_after >= settled_at` exactly (no clock involved) |
| N3a-13 | 9.1 | "integers no larger than 2⁵³": negatives, null and duplicate member names are not addressed | Integers within ±2⁵³ accepted; null and fractions rejected. Duplicate members: `serde_json` keeps the last, and both the signature and the typed view read that same value |
| N3a-14 | 9.1 | How the served document is serialized | Verification accepts any JSON serialization; `Manifest::sign` serves JCS with `sig` added |
| N3a-15 | 9.1 | "a path ending in `/*` matches every path below it": does `/files/*` match `/files` or `/files/`? | Matches every path that starts with `/files/`, including `/files/`; not `/files` |
| N3a-16 | 8.1 | Unknown odd records in 240 to 1000 of a Response | Ignored and dropped from the parsed view (no signature covers them). The Offer keeps them in `signature_unknown` |
| N3a-17 | 8.2 | `detail` "at most 256 bytes" on receive | MALFORMED when longer; `ErrorObject::with_detail` cuts at a character boundary |
| N3a-18 | 4.4 client | "`info`, if present, is on the origin the offer came from" | `same_origin`: the URI starts with the RFC 6454 origin, followed by `/`, `?`, `#` or nothing |
| N3a-19 | 14 / BIP-340 | The official BIP-340 rows 15 to 18 use messages that are not 32 bytes | Skipped: the secp256k1 0.29 API (via `bitcoin` 0.32) takes 32-byte messages only. Every socket message is a 32-byte tagged hash |

### Tests

- `tests/vectors.rs`: every value in `vectors.json` (tagged hash, BigSize,
  tu64, HTTP action and route scope, the route offer bytes, OfferID and
  `offer_sig`, `offer_native` with and without native, the credential
  Context, Digest, witness, length, UseIds, ReplayKey and other-binding
  Digest, `attest_only`, `native`, `rail_id`, the Response bytes and ack,
  the manifest JCS and sig), each rebuilt from the inputs `bnap_ref.py`
  uses; plus the base64url prefixes of the 10.3 example.
- `tests/bip340.rs`: the official BIP-340 vectors, rows 0 to 14
  (`tests/data/bip340-test-vectors.csv`, credited in `tests/data/README.md`).
- `tests/negative.rs`: the conformance negatives of draft-00 section 14 that
  the core can decide (non-minimal BigSize, order, unknown even type, a
  flipped bit at every position of an offer and a Response, an offer without
  `mac` under a key the gate does not hold, class O or native in a route
  offer, attest list out of order, binding with no class S scheme, manifest
  rollback and double rotation), plus record rules and size limits.
- `tests/props.rs`: proptest roundtrips (BigSize, tu64, lp, TLV, entry
  lists, Offer, Credential, Response, Error object) and never-panic
  properties for every parser on arbitrary bytes, TLV-shaped input, mutated
  valid objects and arbitrary JSON.

#### Status at hand-off

- `cargo-q nextest run -p bnap-core`: 75 tests, 75 passed (unit tests,
  `vectors`, `bip340`, `negative`, `props`).
- `cargo-q clippy -p bnap-core --all-targets -- -D warnings`: clean
  (workspace lints, `clippy::pedantic` included).
- `RUSTDOCFLAGS="-D warnings" cargo-q doc -p bnap-core --no-deps`: clean.
- `ops/leak-guard.sh`: clean. No `unsafe` (the workspace forbids it).

### Merge notes

- `Cargo.lock` gained the dependency tree of `bnap-core` (bitcoin 0.32 with
  secp256k1 0.29, sha2 0.11, hmac 0.13, hex, serde, serde\_json,
  serde\_json\_canonicalizer 0.4, thiserror 2; proptest and base64 for
  tests). If it conflicts with another node's lock, regenerate it rather
  than hand-merging. No workspace dependency was added.
- `serde_json_canonicalizer` turns on `serde_json/float_roundtrip` for the
  whole workspace through feature unification.

### Known gaps (for downstream nodes)

- No pricing (section 7), use store commit, settle or replay logic (6.3,
  6.4): `bnap-core` provides the IDs and keys those need. (Done in part B.)
- No base64url: carriers encode and decode headers themselves.
- The HTTP carrier still has to combine repeated fields (RFC 9110 5.3), cap
  credentials at `HTTP_MAX_CREDENTIAL`, compare `BNAP-Context`, and reject
  a request with more than one value credential (5.4).
- Client spend policy (4.4) is not modelled.
- Route `require` is carried as raw JSON values; its semantics belong to
  the judge.
- GREASE values need caller randomness (`tlv::grease_type(seed)` maps a seed
  to a GREASE type).

## Part B: socket semantics and the plug traits

Branch `node/n3-core`. New modules in `crates/bnap-core` (`pricing`,
`policy`, `store`, `outcome`, `sign`, `test_support`) and the whole of
`crates/bnap-plug`. Part A's modules are unchanged except for two
visibility widenings, listed under "Changes to part A files".

### Public API: `bnap-core`

| Module | What it exposes |
| --- | --- |
| `pricing` (section 7) | `VerifiedAttest` (`new`, `with_quota_id`), `QuotaUse`, `PriceDecision` (`price`, `price_wide`, `quota_counter`; fields `waive`, `discounts`, `quota`, `ignored`), `decide`, `quota_candidates`, `Backing { source, amount, unit }`, `BackingSource::{Rail(RailId), Note(local id)}`, `backed_value`, `PayValue { scheme, claimed, backing }`, `AdmitInput`, `admit`, `Admission` (private fields; `decision`, `price`, `pay`, `metered`, `settle`), `AdmittedPay` (private fields; `index`, `scheme`, `unit`, `amount`, `rate`, `claimed`, `backed`, `value`, `backing`), `Charge`, `ChangeCap` (sealed; `get`, `unit`, `status`), `PriceError` (`code`; `Policy`, `Underpaid`, `NotOffered`, `UnitMismatch`), `NO_PAY_BASE`, `metered_entry_allowed` |
| `policy` (section 11) | `PROPERTIES` (embedded table), `PropertyDef` (`rank`, `value`, `applies`), `property`, `PartKind`, `Part` (`known`, `unknown`), `PropertyVector`, `EffectiveVector` (`compute`, `rank`, `value`, `to_tokens`), `Require` (`parse`, `from_pairs`, `satisfied_by`), `RoutePolicy` (`admits`, `select`), `Candidate`, `Selection`, `PolicyError` |
| `store` (6.2 to 6.4) | `UseStore` (async trait), `OutcomeRecord` (`pending`, `needs_refund`; field `refund_recorded`), `OutcomeStatus`, `CounterUse`, `UseModel`, `SchemeUses`, `PlanInput` (takes `admission: &Admission`), `CommitPlan` (`build` is the only constructor; `replay_key`, `ids`, `singles`, `counters`, `now`), `PlanError`, `Commit`, `Settlement` (`new`, `with_scheme_result`, `with_response`), `Settle`, `StoreError`, `UseTable`, `logic::{commit, settle, expire_pending, record_refund, purge}` |
| `outcome` (section 6) | async `commit`, `settle`, `record_refund` (takes `Option<&[u8]>`), `sweep`, `admit`, all generic over `S: UseStore + ?Sized`; `Admitted::{New, Replay}`, `Replay` (`record`, `needs_refund`, `receipt`), `ReceiptInput`, `receipt` (`None` while PENDING or while a refund is due), `CommitError` (`code`, `retry_after`, `to_error_object`), `SettleError`, `AdmitError`, `Sweep` |
| `sign` | `CoreMessage` (sealed; `purpose`, `key`, `digest`, `sign_with`, `verify`), `Purpose` (`key_use`, `tag`), `UnsignedOffer` (`new`, `message`, `finish`, `finish_with_limit`), `UnsignedResponse` (same), `SignError` |
| `test_support`, feature `test-support` | `MemoryStore` (`new`, `set_unavailable`, `inspect`), `MemoryTable`, `block_on` |

### Public API: `bnap-plug`

| Module | What it exposes |
| --- | --- |
| `scheme` | `CredentialScheme` (`id`, `offer`, `native`, `verify`, `settle`, `recover_native`), `Verified { use_ids, rail_ids, value, quota_id }` (`uses`, `quota_use_id`), `LocalId`, `RailRef`, `OfferCtx`, `OfferRole`, `SchemeOffer`, `NativeCtx`, `NativeArtifact`, `Entry`, `VerifyCtx`, `SettleCtx`, `NativeCredential`, `SchemeError` (`rejected`, `code`, `to_error_object`) |
| `signer` | `Signer` (`schnorr`, `verify_unblinded(keyset, unit, amount, y, c)`, `blind_sign(keyset, outputs, &ChangeLimit)`), `CappedSigner` (`verify_only(inner, unit)`, `for_change(inner, &ChangeCap, ReplayKey) -> (CappedSigner, SettleGuard)`, `cap`, `remaining`, `unit`, `notes`, `verify_unblinded`, `blind_sign`), `SettleGuard` (`close`, closes on drop), `ChangeLimit { replay_key, status, unit, cap }`, `ChangeLedger` (`new`, `reserve`, `total`, `forget`), `Point`, `KeysetId`, `BlindedOutput`, `BlindSignature`, `Dleq`, `SignerError` |
| `rail` | `FundingRail` (`kind`, `request`, `status`, `confirm`), `confirm_rail_id -> RailPayment`, `RailPayment { rail_id, amount, unit }` (`backing`), `PayId`, `PayRequest`, `PayState`, `Confirmed { canonical, state, amount, unit }`, `RailError` |
| `carrier` | `Carrier` (associated `Request` and `Response`; `name`, `action_scope`, `route_scope`, `extract`, `offer`, `receipt`, `error`), `RawCredential`, `Challenge`, `NativeChallenge` |
| `policy` | `Pricer`, `PricerError`, `Judge` (`admit`, `after`), `Decision` (`error`), `Action` |
| `pay` | `PaySource`, `Budget`, `PayProof`, `PayError`, `within_budget` |
| re-exports | `UseStore`, `Commit`, `CommitPlan`, `OutcomeRecord`, `Settle`, `Settlement`, `StoreError`, `CoreMessage`, `ChangeCap`, `Properties` (= `EffectiveVector`) |

Every async trait uses `async-trait`, so each plug can be held as
`Arc<dyn Trait>`; `tests/plugs.rs` drives them all that way. `Carrier` is
synchronous: it only transforms requests and responses.

### How a gate runs a request (after part A's 4.4 checks)

`tests/plugs.rs` (`Gate::verify_and_admit` and `Gate::handle`) is this
flow as running code.

1. Verify each part: `let view = CappedSigner::verify_only(signer,
   &entry.unit)`, then `scheme.verify(part, &VerifyCtx { signer: &view,
   .. })`. Verification reads no use state, so a replay always reaches
   step 5. The view keeps every note the signer accepted, once per `Y`.
2. Confirm each `RailRef` with the rail plug of its kind:
   `confirm_rail_id(rail, &r)` refuses a payment that is not `Paid` and
   returns a `RailPayment` (the `RailId`, computed from the rail's own kind
   and bytes, plus the rail's amount and unit).
3. `outcome::admit(store, &AdmitInput { offer, pay: Some(PayValue {
   scheme, claimed: verified.value, backing }), attest, now })`, where
   `backing` is every `payment.backing()` plus `view.notes()`. Admission
   counts `min(claimed, backing)` in the entry's unit (`sat` and `msat`
   convert exactly; any other unit is `BAD_CREDENTIAL`), reads the quota
   counters and returns the `Admission` (POLICY, UNDERPAID, `NOT_OFFERED`,
   `BAD_CREDENTIAL` or UNAVAILABLE otherwise). Build `VerifiedAttest` with
   the registry class and `verified.quota_use_id(scheme)`.
4. `CommitPlan::build(&PlanInput { context, pay_body, attest_bodies,
   schemes: &[verified.uses(id, model), ..], rail_ids, admission:
   &admission, offer_expires, now, replay_window })`. The plan always
   takes the quota counter and every backing payment and note from the
   admission. `PlanError::OutlivesRecord` is POLICY.
5. `outcome::commit(store, &plan, &limits)`:
   - `Admitted::New`: run the action; `let charge = admission.settle(status,
     units)`; `let (capped, guard) = CappedSigner::for_change(signer,
     &charge.cap, *plan.replay_key())`; `scheme.settle(part, &verified,
     &SettleCtx { .. }, &capped)`; `guard.close()` as soon as it returns;
     then `outcome::settle(store, rk, &Settlement::new(&charge,
     now).with_scheme_result(r).with_response(kept))`:
     - `Ok(record)`: `outcome::receipt(&record, &input, false)`.
     - `Err(SettleError::AlreadySettled(record))`: the action outlived
       `pending_timeout` and the timeout won. Discard the `scheme_result`
       and the change just computed (none of it was sent). If
       `record.needs_refund()`, run the refund below and answer from the
       record it returns; otherwise answer from `record`. Either way
       `outcome::receipt(&record, &input, false)`: it answers this request,
       so it is not `replayed`.
     - Any other error: UNAVAILABLE.
   - `Admitted::Replay(r)`: if `r.needs_refund()`, run the refund and
     answer `outcome::receipt(&refunded, &input, true)`; otherwise
     `r.receipt(&input)`.
   - `Err(e)`: answer `e.to_error_object()` (SPENT, PENDING or
     `RATE_LIMITED` with `retry_after`, UNAVAILABLE).

   **The refund** of a timed-out outcome: `let charge =
   admission.settle(Status::Failed, 0)`, `scheme.settle` under
   `CappedSigner::for_change(signer, &charge.cap, rk)` with the guard
   closed when it returns, then `outcome::record_refund(store, rk,
   result.as_deref())` (first write wins; `None` when the scheme has
   nothing to refund). `receipt` and `Replay::receipt` return `None` while
   a refund is due, so this step cannot be skipped.
6. Sign the receipt: `let u = UnsignedResponse::new(&fields)?`, `let sig =
   signer.schnorr(u.message()).await?`, `u.finish(&sig)?`. Never send the
   Response, or any change in it, before step 5's settle (or
   `record_refund`) returned.
7. Run `outcome::sweep(store, now, &limits)` periodically: PENDING past
   `pending_timeout` goes to FAILED, settled records past `replay_window`
   are deleted, single uses stay. A signer using `ChangeLedger` may
   `forget` a `ReplayKey` once its replay window has passed.

Offers are signed the same way: `UnsignedOffer::new(&fields, Some(&k_mac))`,
`signer.schnorr(u.message())`, `u.finish(&sig)`.

### Decisions made

- **`UseStore` lives in `bnap-core`** (`store`), not `bnap-plug`: the
  outcome state machine is generic over it, and `bnap-plug` depends on
  `bnap-core`. `bnap-plug` re-exports it. This added `async-trait` to
  `bnap-core`, a compile-time macro; the crate still does no I/O.
- **The store contract is the `logic` module.** Each `UseStore` method
  behaves exactly as the `store::logic` function of the same name, run as
  one serializable, durable transaction. Key-value stores can implement
  `UseTable` and call `logic` directly; SQL stores write the same rules in
  SQL. `MemoryStore` is the reference implementation.
- **Only bnap-core makes a `CommitPlan`**: its fields are private, so no
  plug can choose a `ReplayKey` or name a use ID in another scheme's space.
- **Sealed signer messages.** `Signer::schnorr` takes `&CoreMessage`, which
  has no public constructor; `UnsignedOffer` and `UnsignedResponse` are the
  only sources, and their `finish` checks the signature under the object's
  own key and re-parses the object. A compile_fail doctest in each crate
  shows that neither a `CoreMessage` literal nor raw bytes compile.
- **`CappedSigner` has no message signing at all.** Schemes get only it, so
  a scheme can never get an offer or a receipt signed, even though
  `UnsignedResponse` is public. Its verify-only view signs nothing.
- **The change cap is a budget for one settlement, enforced twice.**
  In process, `for_change` makes one `Budget` (an `AtomicU64` of what is
  left): every `blind_sign` takes its outputs' sum out of it with a
  compare-and-swap before the signer is called, clones share it, a sum
  that overflows is above any cap, and the `SettleGuard` the gate holds
  closes it when `settle` returns, so a kept clone signs nothing. A call
  that fails after the reservation keeps its share spent, since the signer
  may have signed. At the signer, every call carries a `ChangeLimit`
  (`ReplayKey`, status, unit, total cap), and the signer MUST keep a
  running total per settlement; `ChangeLedger` does this, counting each
  distinct output (keyset, amount, `B'`) once, so a deterministic settle
  that runs again signs the same notes for nothing, and pinning the first
  cap a settlement is named with (ERRATA N3b-16). The signer also refuses
  a keyset that is not in the limit's unit.
- **`ChangeCap` is sealed, and so is its source.** `Admission` and
  `AdmittedPay` have private fields and only `pricing::admit` makes them
  (a compile_fail doctest shows an `Admission` literal does not compile),
  so `Admission::settle` is the only way to a `ChangeCap` and the cap is
  always `value - charged` for an admitted value. `ChangeCap` carries the
  entry's unit and the settlement's status.
- **Value is what operator-trusted plugs confirmed.** `admit` counts
  `min(scheme claim, backing)` where backing is the rails' confirmed
  amounts and the notes the signer's verify-only view accepted, each
  counted once (ERRATA N3b-15). `Backing` has public fields: the gate,
  which is trusted, builds it from `RailPayment::backing` and
  `CappedSigner::notes`; schemes never see `AdmitInput`. Every backing
  payment and note is a single use in the commit plan, so a scheme cannot
  count a payment or a note it does not let the socket consume.
- **The admission binds the commit.** `PlanInput` takes `&Admission`; the
  plan adds its quota counter and backing itself, so a gate cannot price a
  request at 0 by a quota and commit it without consuming the quota.
- **No receipt before the refund.** `receipt` returns `None` for a
  timed-out outcome whose refund is not recorded (`refund_recorded`), on
  both refund paths (ERRATA N3b-17).
- **`Verified.rail_ids` are rail references** (`RailRef { kind, reference }`)
  that the rail confirms, per draft-00 6.1 and ERRATA row 19; the field
  keeps the overview's name. `Verified` adds `quota_id`, the local ID of
  the registry's `quota_id` identity.
- **`UseModel::Rate { k, epoch }`**: the registry says only `rate`, so `k`
  and `epoch` come from the gate's configuration.
- **Settlement charges**: OK non-metered is the admitted price; OK metered
  is `min(price(⌈units × rate / 1000⌉), price(amount))` in 128 bits under
  the admission's decision (no second quota use); FAILED is 0 with a cap of
  the whole value. "Value" is always the admitted `min(claimed, backing)`.
  Overpayment is left to the scheme, up to the cap.
- **Property order** comes from `policy::PROPERTIES`, a table copied from
  the registry's `properties.toml` (twelve properties, tokens weakest
  first, `applies_to`). It is to be replaced by the registry export; keep
  the same API. Property vectors themselves are passed in by the caller
  (from the registry entries), never taken from a plug.
- **Async tests without tokio**: `test_support::block_on` polls with a no-op
  waker, enough for `MemoryStore`. The concurrent race uses OS threads and
  a barrier against the store's mutex.

### ERRATA list, part B

| # | Where | Ambiguity | What the build does |
| --- | --- | --- | --- |
| N3b-1 | 7, admit | `p = price(entry.amount, or 0 if the credential has no pay)` makes `price(0) = 0` always, so `if p > 0 and no pay -> UNDERPAID` can never fire, and a credential with no `pay` and any attestation (a discount, or one that failed verification) is admitted for free | **Not the literal reading, because it is a free-admission bypass.** Without pay the base is `NO_PAY_BASE` (2⁶⁴ − 1): admitted only when verified attestations alone make the price 0 (a waive, a 10,000 bp discount, or a quota with room). Owner decision needed |
| N3b-2 | 6.4, 8.1 | What a FAILED outcome charges | 0, with the whole value as the refund cap (as the notes draft-00 7.1 reads it) |
| N3b-3 | 6.3 | `singles` and `counters` named twice by one credential; the literal loop increments a counter twice | Both are sets: each ID and counter commits once. The `ReplayKey` keeps duplicates (N3a-9) |
| N3b-4 | 6.1 | The `expires + 60 <= now + replay_window` rule has no error code | POLICY |
| N3b-5 | 11 | "Per-property minimum over its scheme, rail and verifier entries, with unknown counted as weakest": read literally, a rail entry has no binding, so every effective binding would be `none`, against the section 11 example | A property counts only the entries whose kind it applies to (registry `applies_to`, N2-2 and N2-3). Within those, a missing value, an unknown token or a missing registry entry is the weakest. A property that applies to no part (refund for an attestation) does not constrain it |
| N3b-6 | 6.4 | Is `replay_window` measured from commit or from settlement? | From commit (`created`), matching 6.1's `now + replay_window` at commit |
| N3b-7 | 6.4 | A record past `replay_window` that the sweep has not deleted yet | SPENT, as if deleted, so the answer does not depend on sweep timing |
| N3b-8 | 8.2; overview, Judge | No code for a judge that queues or refuses | Queue is `RATE_LIMITED` with `retry_after`; refuse is POLICY |
| N3b-9 | 9.1 `require` | An unknown property or value token | The route is refused at start-up (`PolicyError`), never ignored |
| N3b-10 | 9.1; overview rules | `allow_experimental` is an overview rule with no manifest member | `RoutePolicy::allow_experimental`, from gate configuration; experimental means effective `maturity = experimental` |
| N3b-11 | 7, 11 | A required attestation (effect 0) whose vector fails `require`: dropping it from the offer would lift the requirement | The route is refused at start-up |
| N3b-12 | 6.4 Timeout | "Moves to FAILED, with the refund that implies", but nothing records the refund | The refund is computed by the first request to reach the timed-out record, the client's replay or the late action's own settle: settle FAILED with charge 0, then `record_refund` records it once (as the notes draft-00 7.5 reads it) |
| N3b-13 | 6.4 | A replay after `pending_timeout` but before the sweep ran | The replay times the outcome out at once and proceeds as a FAILED replay |
| N3b-14 | 6.3, 6.4 | `retry_after` values | PENDING: seconds until `created + pending_timeout`; `RATE_LIMITED`: seconds until the full counter's epoch ends; at least 1 |
| N3b-15 | 7 admit, 6.1 | Admission compares the price with "the scheme's verified value", but 6.1 makes schemes untrusted and bnap-plug contains them: read literally, a scheme can cite a real but small payment and claim any value, and the change cap follows the claim | **Not the literal reading.** The value counted is `min(scheme claim, backing)`: payments a rail confirmed as final plus notes the signer verified, each once, in the entry's unit (`sat` and `msat` convert exactly, rounded down; any other unit is refused with `BAD_CREDENTIAL`). Every backing payment and note is committed as a single use. A value scheme with neither (a facilitator scheme) must confirm through a `FundingRail` of its kind. Owner decision needed on the wording of section 7 |
| N3b-16 | 6.4, 7, overview signer | The overview's `blind_sign(.., cap)` takes a per-call cap with no settlement identity, so neither the scheme host nor an out-of-process signer can bound a scheme that calls it repeatedly | Each call names its settlement (`ChangeLimit`: `ReplayKey`, status, unit, total cap) and the signer keeps a running total per `ReplayKey` and status, counting each distinct output once. Totals are per status because a timed-out `ReplayKey` is settled twice (the late OK settle and the FAILED refund) and the status changes exactly once, so at most one is ever recorded and sent. The first cap named for a settlement bounds it. So at most `value - charged` plus `value` is ever signed per `ReplayKey`, and only one of them reaches the client, as long as a scheme has no channel to the client but the gate (true for WASM plugs; compiled-in plugs are first-party). A single total per `ReplayKey` would bound the signing at `value`, but would short an honest client whose late OK settle signed change before the timeout won. Owner decision: keep per status, or require schemes to make the refund a superset of the change |
| N3b-17 | 6.4 Replay | A timed-out outcome whose scheme has nothing to refund leaves `scheme_result` empty, so "refund recorded" cannot be read from `scheme_result` | `OutcomeRecord.refund_recorded` marks it; `record_refund` takes `Option<&[u8]>`; no receipt is made while a refund is due |
| N3b-18 | 6.4, 8.1 `replayed` | The late action whose settle lost to the timeout answers its own request from the recorded FAILED outcome | `replayed` is false: the Response answers the request that ran the action, not a replay |

### Tests, part B

- `src/outcome/tests.rs` (state machine, `MemoryStore`): a concurrent
  double spend of one note by 16 credentials (exactly one wins, one `used`
  entry, one outcome); 12 concurrent retries of one credential (one New,
  the rest PENDING); replay returns the recorded outcome with `replayed`,
  the original `settled_at` and the new Digest, and writes nothing; no
  status flip after settlement (second settle refused, sweep and refund
  leave it alone); same use IDs under another `ReplayKey` are SPENT,
  including a body altered on the path; one Lightning payment through
  L402 and MPP is a conflict and the aborted commit consumes nothing; rate
  counters, `retry_after` and give-back on FAILED; FAILED keeps single
  uses spent; pending timeout, late settle refused, no receipt before the
  refund, refund recorded once on replay; a refund with nothing to return;
  a late settle answering from the FAILED record; replay window edge,
  purge and SPENT after it; PENDING never purged; the 6.1 rule; reusable
  IDs in the `ReplayKey` but not consumed; duplicate IDs; a store outage
  fails closed; a binding change on retry keeps the `ReplayKey`; a quota
  with room at pricing but full at commit; a quota-priced admission always
  commits its counter (the review's probe: five attestation-only requests
  under one per hour give one New and four `RATE_LIMITED`); every backing
  payment and note is consumed even when the scheme names none.
- `tests/pricing.rs`: the price table (two 20% discounts give 36%, waive
  beats discount in either order, bearer attestations cannot waive or
  discount, rounding, the 10.3 example), admission rules, attestation-only
  offers, the no-pay bypass of N3b-1, quota order, room and epochs, the
  10.3 metered charge (340 sat, 1,340 sat of change), products beyond 2⁶⁴,
  overpayment, FAILED; backing (the review's probe of 21 msat against a
  claim of 1,000,000 sat, an underpaying payment, no backing, a payment
  named twice, an overclaim cut to the backing and its cap, msat rounding,
  a wrong unit, a notes claim above the verified notes, unit conversion
  and saturation); proptests for monotonicity and the metered cap.
- `tests/policy.rs`: the overview route example with registry vectors
  (notes, MPP and L402 at binding O, notes alone at A, never a reusable
  bearer), notes funded by card, a custodial facilitator, unknown entries
  and tokens, attestations and credential-only properties, unsatisfiable
  routes, experimental entries, a failing required attestation, `require`
  parsing.
- `tests/sign.rs`: the section 14 offer and Response reproduced byte for
  byte through `UnsignedOffer` and `UnsignedResponse`; wrong keys and bad
  signatures refused.
- `bnap-plug/tests/plugs.rs`: the capped signer (over the cap, overflow,
  two calls whose sum exceeds the cap, 16 concurrent clones that sign 99
  of a 100 cap in 3 sat steps, a clone used after the guard closed, a
  guard dropped at once, a mismatched answer), the signer's running total
  per settlement (two budgets for one settlement, re-signing the same
  outputs, separate refund and outcome totals, a keyset in another unit),
  concurrent refunds of one outcome, the verify-only view keeping each
  accepted note once, a key-use-checking test signer, and the whole gate
  flow through `dyn` plugs (mock L402, MPP and notes schemes, a fake
  Lightning rail, the in-memory store): one payment under two schemes
  admits one action, the replay is re-signed with `replayed`, an
  underpaying rail reference (the review's probe), a payment in another
  unit, a payment that is not final, a notes claim above the verified
  notes, a greedy scheme that signs the cap twice and keeps its signer
  (the review's probe: 46 sat signed in all, the kept clone refused), an
  action that outlives the timeout answering FAILED with its refund, a
  replay after a crash collecting the refund, an unpaid payment never
  reaching commit, an outage failing closed; plus a string carrier, judge
  decisions, budgets and scheme error codes.

#### Status at hand-off, part B (after repair round 1)

- `cargo-q nextest run -p bnap-core -p bnap-plug`: 161 tests, 161 passed
  (138 in `bnap-core`, 23 in `bnap-plug`).
- `cargo-q test --doc -p bnap-core -p bnap-plug`: the three compile_fail
  doctests pass (no `CoreMessage` from raw bytes in either crate, no
  `Admission` literal).
- `cargo-q clippy -p bnap-core -p bnap-plug --all-targets -- -D warnings`,
  with and without `--features bnap-core/test-support`: clean (pedantic
  included, toolchain 1.99.0).
- `RUSTDOCFLAGS="-D warnings" cargo-q doc -p bnap-core -p bnap-plug
  --no-deps`: clean. `cargo-q fmt --check`: clean. `ops/leak-guard.sh`:
  clean.

### Repair round 1

A non-author checker failed part B with five findings. Each is fixed in
its own commit:

| Finding | Fix | Commit |
| --- | --- | --- |
| Change cap exceedable: checked per call, `Clone`, no settlement identity at the signer | Shared budget with compare-and-swap, `SettleGuard`, `ChangeLimit`, `ChangeLedger` | `fix(plug): make the change cap a consumable budget scoped to one settle` |
| Cap follows the scheme's claim; rail amount and unit dropped | `RailPayment`, note tally in the verify-only view, `min(claim, backing)`, units, backing consumed at commit | `fix(core,plug): count only the value the rails and the signer confirmed` |
| `Admission` and `AdmittedPay` fields public, so the `ChangeCap` seal did not hold | Private fields with getters, compile_fail doctest | `fix(bnap-core): make Admission and AdmittedPay fields private` |
| Quota decision not bound to the commit | `PlanInput.admission`; the plan adds the counter | `fix(bnap-core): bind the admission's quota counter to the commit plan` |
| Timeout path: `AlreadySettled` undocumented, refund skippable | Docs for both refund paths, `receipt` withheld while a refund is due, `refund_recorded` | `fix(core): refund a timed-out outcome before any receipt is made for it` |

### Changes to part A files

- `OfferFields::to_stream` and `ResponseFields::to_stream` are
  `pub(crate)` instead of private, so `sign` can serialize without a local
  key. No behaviour change.
- `lib.rs`: the new modules and re-exports. `Cargo.toml`: `async-trait`
  (workspace dependency) and the `test-support` feature.

### Merge notes, part B

- `Cargo.lock` gains `async-trait` and `bnap-plug`'s edges; regenerate it on
  conflict. No workspace dependency was added.
- `bnap-plug` depends on `bnap-core` by path (`../bnap-core`); no crate
  declared an internal dependency before, so there was no pattern to
  follow.
- Downstream crates that want `MemoryStore` add
  `bnap-core = { path = "../bnap-core", features = ["test-support"] }` to
  their dev-dependencies.

### Known gaps and notes for downstream nodes

- **Stores** (`bnap-store-sqlite`, `bnap-store-postgres`): implement
  `UseStore` so each method matches `store::logic`, durably.
  `bnap-store-tests` should run the scenarios of `src/outcome/tests.rs`
  against `&dyn UseStore`, with `MemoryStore` as the reference.
- **Registry**: `policy::PROPERTIES` is an embedded copy of
  `registry/properties.toml`; replace it with the export and add a test
  that the order matches. The gate supplies each entry's vector and its
  binding class; `metered_entry_allowed(refund, upto)` must be called when
  building metered offers, since core has no registry access.
- **Gate** (`caparra-gate`): owns the offer-building loop (Pricer, then
  `scheme.offer`, `OfferID`, `scheme.native`, `UnsignedOffer`), the flow
  above, the per-address and per-offer bounds on plug work (section 12),
  stopping actions at `pending_timeout`, and the sweep schedule.
- **Native credentials** (5.4): `CredentialScheme::recover_native` exists
  with an unsupported default; the native envelope from part A
  (`credential::native_context`, `native_digest`) is not wired into a flow.
- **Signers** (`bnap-signer-file`, `bnap-signer-process`): `schnorr` MUST
  check that the key named by the `CoreMessage` is held for
  `purpose().key_use()`. `verify_unblinded` MUST answer false for a keyset
  not in the given unit. `blind_sign` MUST refuse a keyset not in
  `limit.unit` and MUST keep the running total per settlement:
  `ChangeLedger::reserve` before signing does both the total and the
  dedupe. `ChangeLedger` is in memory; a signer that restarts forgets
  totals, which is safe only because the gate never sends change before
  the outcome is durable. A durable ledger is a later improvement.
- **Schemes** (`bnap-scheme-*`): `Verified.value` is a claim in the chosen
  pay entry's unit, and admission counts it only up to the backing. A
  rail scheme names its payments in `rail_ids`; a notes scheme checks
  every note through `cx.signer.verify_unblinded` (the view uses the
  33-byte `Y` as the note's local ID, which should match the scheme's own
  use IDs); a facilitator scheme (x402, card) needs a `FundingRail` of its
  kind to confirm its payments, or it is always UNDERPAID above price 0.
- **Stores** also need the `refund_recorded` flag and the
  `record_refund(rk, Option<&[u8]>)` rule of `store::logic`.
- Unit conversion is exact only between `sat` and `msat`; any other pair
  is refused. A gate that wants other conversions does them in the Pricer,
  when the offer is built.
- No WIT interface yet (the overview's v0.7 WASM plugs).
- Part A's open review item on duplicate JSON member names in the manifest
  is unchanged by part B.
