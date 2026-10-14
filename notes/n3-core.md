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
| N3a-13 | 9.1 | "integers no larger than 2⁵³": negatives, null and duplicate member names are not addressed | Integers within ±2⁵³ accepted; null and fractions rejected. Duplicate members (updated in the part B re-cut): the document is read as I-JSON (RFC 7493), which JCS assumes, and an object that names a member twice at any depth, escaped spellings included, is refused with `ManifestError::DuplicateMember`. `manifest::parse_strict` is public for other JCS-hashed JSON (the MCP carrier) |
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
`crates/bnap-plug`. Part A's modules changed only as listed under
"Changes to part A files".

Part B failed three checker rounds. After the third, its design was re-cut
rather than patched: the socket's decision for one request is now a single
bnap-core entry point, `outcome::process`, which detects replays before it
prices anything. "The process contract" below states what it guarantees;
"Re-cut (round 3)" lists every input of that round with its status, test
and commit, "Re-cut, repair round 1" the five findings the checkers
raised against the re-cut, and "Re-cut, repair round 2" the two after it
(store conformance under concurrency, and the change ledger moved into
the use store).

### Public API: `bnap-core`

| Module | What it exposes |
| --- | --- |
| `pricing` (section 7) | `VerifiedAttest` (`new`, `with_quota_id`), `QuotaUse`, `PriceDecision` (`price`, `price_wide`, `quota_counter`; fields `waive`, `discounts`, `quota`, `ignored`), `decide`, `quota_candidates`, `Backing { source, amount, unit }`, `BackingSource::{Rail(RailId), Note(Y)}` (`single_id`), `note_id`, `NOTE_TAG`, `backed_value`, `Refund::{None, OutOfBand, Atomic}` (`from_token`, `of`, `as_str`, `returns_change`), `PayValue { scheme, claimed, backing, refund }`, `AdmitInput`, `admit`, `Admission` (private fields; `decision`, `price`, `pay`, `metered`, `settle`), `AdmittedPay` (private fields; `index`, `scheme`, `unit`, `amount`, `rate`, `claimed`, `backed`, `value`, `backing`, `refund`), `Charge` (pure pricing, private fields; `status`, `charged`, `metered_units`, `change`, `unit`), `ChangeCap` (sealed, bound to one outcome; `replay_key`, `get`, `unit`, `status`, `keep_until`), `PriceError` (`code`; `Policy`, `Underpaid`, `NotOffered`, `UnitMismatch`), `NO_PAY_BASE`, `metered_entry_allowed` |
| `note` | `hash_to_curve(secret) -> Option<[u8; 33]>` (NUT-00, checked against the NUT-00 vectors), `DOMAIN_SEPARATOR` |
| `policy` (section 11) | `PROPERTIES` (embedded table), `PropertyDef` (`rank`, `value`, `applies`), `property`, `PartKind`, `Part` (`known`, `unknown`), `PropertyVector`, `EffectiveVector` (`compute`, `rank`, `value`, `to_tokens`), `Require` (`parse`, `from_pairs`, `satisfied_by`), `RoutePolicy` (`admits`, `select`), `Candidate`, `Selection`, `PolicyError` |
| `store` (6.2 to 6.4) | `UseStore` (async trait; `commit(&CommitPlan)`, `counter`, `outcome`, `settle(&SettleRequest)`, `expire_pending(&SweepWindow)`, `record_refund(&RefundRequest)`, `reserve_change(&ChangeRequest)`, `purge(&SweepWindow)`), `OutcomeRecord` (`pending(&plan)`, `needs_refund`; fields `refund_recorded`, `keep_until`, `refund_cap`, `unit`, and the change ledger `change_total`, `change_cap_ok`, `change_outputs`), `OutcomeStatus`, `CounterUse`, `UseModel`, `SchemeUses`, `CommitPlan` (no public constructor; `replay_key`, `ids`, `singles`, `counters`, `now`, `keep_until`, `refund_cap`, `unit`), `PlanError`, `Commit`, `Settlement` (private fields; `new(&OutcomeCharge, settled_at)`, `with_scheme_result`, `with_response`, getters), `SettleRequest`, `RefundRequest`, `SweepWindow`, `ChangeRequest` (each: private fields, getters, no public constructor), `ChangeOutput { keyset, amount, blinded }`, `Reserve::{Reserved { total }, OverCap { total, cap }, NoValue, Settled, Unknown}`, `Settle` (`Settled`, `AlreadySettled`, `ChangeOverCap { total, cap }`, `Unknown`), `StoreError`, `UseTable`, `logic::{commit, settle, expire_pending, record_refund, reserve_change, purge}` |
| `outcome` (section 6) | async `process` (the one entry point), `settle(store, &Pending, &Settlement, &Limits)`, `record_refund(store, &Recorded, Option<&[u8]>)`, `reserve_change(store, &ChangeCap, &[ChangeOutput])`, `sweep`, all generic over `S: UseStore + ?Sized`; `Request` (what the gate verified), `Admitted::{New(Pending), Replay(Recorded)}`, `Pending` (sealed; `replay_key`, `admission`, `charge -> OutcomeCharge`), `OutcomeCharge` (sealed; `replay_key`, `status`, `charged`, `metered_units`, `cap`), `Recorded` (sealed; `replay_key`, `record`, `replayed`, `needs_refund`, `refund_cap`, `receipt`, `unsigned_receipt`), `ReceiptInput`, `ProcessError` (`code`, `retry_after`, `to_error_object`; `Spent`, `Pending`, `RateLimited`, `Stale`, `Price`, `Plan`, `Store`), `SettleError` (`AlreadySettled(Box<Recorded>)`, `Unknown`, `WrongOutcome`, `ChangeOverCap { total, cap }`, `Store`), `Sweep` |
| `limits` (part A module, extended) | `Limits::from_manifest` now returns `Result<Limits, LimitsError>`; `REFUND_MARGIN`, `LimitsError::ReplayWindowTooShort`, `min_replay_window`, `validate`, `check_offer_lifetime`, `record_window` |
| `sign` | `CoreMessage` (sealed; `purpose`, `key`, `digest`, `sign_with`, `verify`), `Purpose` (`key_use`, `tag`), `UnsignedOffer` (`new`, `message`, `finish`, `finish_with_limit`), `UnsignedResponse` (`message`, `finish`, `finish_with_limit`; no public constructor, only `Recorded::unsigned_receipt` makes one), `SignError` |
| `test_support`, feature `test-support` | `MemoryStore` (`new`, `set_unavailable`, `inspect`, `reloaded`), `MemoryTable`, `block_on`, `sign_response`, `sign_response_with_limit` and `unsigned_response` (Response fields signed outside any recorded outcome, for codec tests and vectors), `conformance` (`run`, `Executor`, `Spin`, `THREADS`, `ROUNDS`, and each scenario as a function) |

### Public API: `bnap-plug`

| Module | What it exposes |
| --- | --- |
| `scheme` | `CredentialScheme` (`id`, `offer`, `native`, `verify`, `settle`, `recover_native`), `Verified { use_ids, rail_ids, value, quota_id }` (`uses`, `quota_use_id`), `LocalId`, `RailRef`, `OfferCtx`, `OfferRole`, `SchemeOffer`, `NativeCtx`, `NativeArtifact`, `Entry`, `VerifyCtx`, `SettleCtx`, `NativeCredential`, `SchemeError` (`rejected`, `code`, `to_error_object`) |
| `signer` | `Signer` (`schnorr`, `verify_unblinded(keyset, unit, amount, secret, c) -> Option<Point>`, the signer deriving `Y = hash_to_curve(secret)` itself; `blind_sign(keyset, outputs, &ChangeLimit)`, a running total per `ReplayKey` kept at least until `limit.keep_until`, as a second line behind the store's reservation; an empty batch or an output of amount 0 MUST be refused), `CappedSigner` (`verify_only(inner, unit)`, `for_change(inner, store, &ChangeCap) -> (CappedSigner, SettleGuard)`, `cap`, `remaining`, `unit`, `notes`, `verify_unblinded(keyset, amount, secret, c) -> Option<Point>`, `blind_sign`, which reserves in the store before the signer is called), `SettleGuard` (`close`, closes on drop), `ChangeLimit { replay_key, status, unit, cap, keep_until }`, `ChangeLedger` (`new`, `reserve`, `total(rk)`, `forget_expired(now)`), `Point`, `KeysetId`, `BlindedOutput`, `BlindSignature`, `Dleq`, `SignerError` |
| `rail` | `FundingRail` (`kind`, `request`, `status`, `confirm`), `confirm_rail_id -> RailPayment`, `RailPayment { rail_id, amount, unit }` (`backing`), `PayId`, `PayRequest`, `PayState`, `Confirmed { canonical, state, amount, unit }`, `RailError` |
| `carrier` | `Carrier` (associated `Request` and `Response`; `name`, `action_scope`, `route_scope`, `extract`, `offer`, `receipt`, `error`), `RawCredential`, `Challenge`, `NativeChallenge` |
| `policy` | `Pricer`, `PricerError`, `Judge` (`admit`, `after`), `Decision` (`error`), `Action` |
| `pay` | `PaySource`, `Budget`, `PayProof`, `PayError`, `within_budget` |
| re-exports | `UseStore`, `Commit`, `CommitPlan`, `OutcomeRecord`, `Settle`, `Settlement`, `SettleRequest`, `RefundRequest`, `SweepWindow`, `ChangeRequest`, `ChangeOutput`, `Reserve`, `StoreError`, `CoreMessage`, `ChangeCap`, `Properties` (= `EffectiveVector`) |

Every async trait uses `async-trait`, so each plug can be held as
`Arc<dyn Trait>`; `tests/plugs.rs` drives them all that way. `Carrier` is
synchronous: it only transforms requests and responses.

### How a gate runs a request (after part A's 4.4 checks)

`tests/plugs.rs` (`Gate::verify` and `Gate::handle`) is this flow as
running code. The gate verifies and confirms; the order of the socket's
own steps is not the gate's to choose, because `outcome::process` runs
them.

1. Verify each part: `let view = CappedSigner::verify_only(signer,
   &entry.unit)`, then `scheme.verify(part, &VerifyCtx { signer: &view,
   .. })`. Verification reads no use state. A scheme names a note by its
   secret (`view.verify_unblinded(keyset, amount, secret, c)`), never by
   its point: the signer and the view each derive `Y =
   hash_to_curve(secret)` and the view keeps every note the signer
   accepted, once per that `Y` (N3b-28).
2. Confirm each `RailRef` with the rail plug of its kind:
   `confirm_rail_id(rail, &r)` refuses a payment that is not `Paid` and
   returns a `RailPayment` (the `RailId`, computed from the rail's own kind
   and bytes, plus the rail's amount and unit).
3. Call `outcome::process(store, &Request { offer, context, pay_body,
   attest_bodies, schemes: &[verified.uses(id, model), ..], rail_ids, pay:
   Some(PayValue { scheme, claimed: verified.value, backing, refund }),
   attest, now }, &limits)`. `backing` is every `payment.backing()` plus
   `view.notes()`; `refund` is the scheme's registered refund property
   (`Refund::from_token` of the registry entry's `refund`, or
   `Refund::of(&effective_vector)`), never the plug's word; `attest` holds
   a `VerifiedAttest` per verified attestation, with the registry class and
   `verified.quota_use_id(scheme)`. `process` then runs, in this order:
   1. it collects every `UseId` and `RailId` and computes the `ReplayKey`,
      which needs no admission (`store::Uses`);
   2. it looks up `outcome[rk]`. A known credential is classified **before
      any pricing**: PENDING inside `pending_timeout`
      (`ProcessError::Pending` with `retry_after`); timed out at once past
      it (N3b-13); SPENT past the record window (N3b-7); otherwise
      `Admitted::Replay(recorded)`;
   3. only for a new credential: STALE if the offer or the chosen entry's
      quote expired; admission (section 7, quota counters read from the
      store: POLICY, UNDERPAID, `NOT_OFFERED`, `BAD_CREDENTIAL`); the
      commit plan (POLICY for an offer that outlives the record, 6.1); and
      the store's commit, which re-checks every single use and every counter
      in one transaction: `Admitted::New(pending)`, SPENT or `RATE_LIMITED`.
      If the same credential committed between the lookup and this commit,
      the record is classified as in step 2. If the fresh path fails before
      the commit (STALE, POLICY, UNDERPAID, a plan error), `outcome[rk]` is
      read once more and a record found is classified as in step 2: a copy
      of the same credential that committed after the lookup is what filled
      the quota this copy priced against.
4. On `Admitted::New(pending)`: run the action; `let charge =
   pending.charge(status, units)` (an `OutcomeCharge`, bound to the
   outcome); `let (capped, guard) = CappedSigner::for_change(signer,
   store, charge.cap())` (the store that committed the outcome: every
   output is reserved in its record before the signer signs it);
   `scheme.settle(part, &verified, &SettleCtx { status:
   charge.status(), charged: charge.charged(), .. }, &capped)`;
   `guard.close()` as soon as it returns; then `outcome::settle(store,
   &pending, &Settlement::new(&charge, now).with_scheme_result(r)
   .with_response(kept), &limits)`:
   - `Ok(recorded)`: answer from it.
   - `Err(SettleError::AlreadySettled(recorded))`: the timeout won, through
     a sweep, a replay, or this settle itself coming after `created +
     pending_timeout` (N3b-24). Discard the `scheme_result` and the change
     just computed (none of it was sent). If `recorded.needs_refund()`, run
     the refund below and answer from the `Recorded` it returns; otherwise
     answer from `recorded`. Either way the answer is not `replayed`
     (N3b-18): core set the flag.
   - `Err(SettleError::ChangeOverCap { .. })`: an OK settle of an outcome
     with more change reserved than OK leaves (`value - charged`; the
     scheme signed under the FAILED cap), a gate bug answered UNAVAILABLE.
     Nothing was written: settle the outcome FAILED instead.
   - Any other error (`Unknown`, `WrongOutcome`, `Store`): UNAVAILABLE.
5. On `Admitted::Replay(recorded)`: if `recorded.needs_refund()`, run the
   refund below; otherwise answer from `recorded`, which has `replayed`
   set.
6. On `Err(e)`: answer `e.to_error_object()`.

**The refund** of a timed-out outcome: `let cap =
recorded.refund_cap().unwrap()` (status FAILED, the cap the commit recorded:
the admitted value for an `atomic` scheme, 0 otherwise, N3b-26, bound to
the outcome's `ReplayKey`), `scheme.settle` with status FAILED and charge 0
under `CappedSigner::for_change(signer, store, &cap)`, the guard closed
when it returns, then `outcome::record_refund(store, &recorded,
result.as_deref())` (first write wins; `None` when the scheme has nothing to refund; a
credential without pay has no value scheme to settle and records `None`),
and answer from the `Recorded` it returns. `Recorded::receipt` and
`Recorded::unsigned_receipt` return `None` while a refund is due, so no
answer is made before a refund is recorded. Core cannot see whether the scheme's FAILED settle ran, so the
gate MUST NOT call `record_refund` without running it.

7. Sign the receipt: `let u = recorded.unsigned_receipt(&ReceiptInput {
   .. }).unwrap()?`, `let sig = signer.schnorr(u.message()).await?`,
   `u.finish(&sig)?`. `unsigned_receipt` is the only way to get a Response
   signed and returns `None` while the outcome is PENDING or its refund is
   due, so no receipt, and no change in it, can be signed before step 4's
   settle (or `record_refund`) is recorded.
8. Run `outcome::sweep(store, now, &limits)` periodically: PENDING past
   `pending_timeout` goes to FAILED; settled records past
   `limits.record_window()` are deleted once `keep_until + 60` has passed
   (N3b-25, one clock skew for the gate's other clocks); single uses stay.
   A signer using `ChangeLedger` calls `forget_expired(now)`, which drops
   an outcome's total only once `ChangeLimit::keep_until` plus a clock
   skew has passed (the earliest time the store may purge the record).
   The store's own ledger goes with the record.

### The `process` contract

`outcome::process(store, &request, &limits) -> Result<Admitted,
ProcessError>` is the socket's whole decision for one verified request.

- **Input.** `Request` holds only what the gate verified: the checked
  offer, the Context, the bodies, every scheme's local IDs under its
  registry model, the confirmed `RailId`s, the pay claim with its backing
  and registered refund property, the verified attestations and the clock.
  Nothing in it is read from the store.
- **The `ReplayKey` comes first.** It is computed from the Context, the
  bodies, the schemes' `UseId`s and the `RailId`s (6.1), never from an
  admission.
- **Replay detection before pricing.** `outcome[rk]` is read before any
  admission. A known credential never reaches pricing, so quota counters
  its own commit consumed can never misprice or refuse its replay, and its
  refund is the cap its commit recorded, never one priced again (N3b-23,
  N3b-26).
- **A new credential is priced once and committed with what it was priced
  on.** The plan always carries the quota counter the admission chose and
  every payment and note it counted as value (N3b-19). The store's commit
  re-checks every single use and every counter limit in one serializable
  transaction, so a pricing read that is stale by then aborts with
  `RATE_LIMITED` and consumes nothing (section 7): it can never admit more
  than the store allows.
- **A copy that missed its own commit is answered from the record.** When
  the fresh path fails before the commit (STALE, POLICY, UNDERPAID, a plan
  error), `process` reads `outcome[rk]` again and classifies a record it
  finds (PENDING, or a replay). The commit writes the counter increment and
  the record in one transaction, so a read that saw the full counter also
  sees the record: two copies of one quota-priced credential presented at
  once give one New and one PENDING, never UNDERPAID.
- **A fresh commit needs a live offer.** A credential the store does not
  know, on an offer or quote that expired (60 s skew), is STALE; a known
  one is still answered from its outcome (the core side of N3b-22).
- **No other path.** `CommitPlan` has no public constructor and the
  store-reading admission is private (compile_fail doctests in
  `outcome::Pending`); `settle` takes the `Pending` only `process` makes;
  every answer is a `Recorded`, whose `replayed` flag core sets. Every
  write the store takes is sealed the same way: `SettleRequest`,
  `RefundRequest` and `SweepWindow` have no public constructor, a
  `Settlement` is built only from the `OutcomeCharge` of a `Pending` and
  carries its `ReplayKey` (`settle` refuses one made for another outcome
  with `WrongOutcome`), and a `ChangeCap` carries the `ReplayKey` it was
  computed for, so `CappedSigner::for_change` takes no `ReplayKey` of
  its own, only the cap and the store that keeps the outcome's change
  ledger; `ChangeRequest` is sealed the same way (compile_fail doctests
  in `store` and `bnap_plug::signer`). The pure
  `pricing::admit` stays public for offers and tests, but an `Admission`
  alone commits nothing and its `Charge` grants no change budget.
- **One change ledger per outcome, in the store** (N3b-29). Every output
  a scheme gets signed as change or a refund is reserved first, with
  `outcome::reserve_change`, in `outcome[rk]`, in one store transaction:
  one running total across the OK change and every FAILED refund, each
  distinct output once, never above the admitted value. The store is
  durable and shared, so neither a signer restart nor a second signer
  or gate instance opens a new budget for an outcome whose value was
  signed, and the ledger lasts exactly as long as the record.
- **What stays the gate's to keep.** Core cannot see a plug call: it
  cannot check that the scheme's FAILED settle ran before `record_refund`,
  or that the action ran before `settle`. The gate MUST NOT record a
  refund it did not compute.

| `process` returns | Meaning | Gate step |
| --- | --- | --- |
| `Ok(Admitted::New(pending))` | Committed, PENDING | Run the action, then `settle` |
| `Ok(Admitted::Replay(recorded))` | Same credential, same request, settled or just timed out | Refund first if due, answer with `replayed` |
| `Err(Pending { retry_after })` | Same credential in flight | PENDING |
| `Err(Spent)` | A single used under another `ReplayKey`, or the record window passed | SPENT |
| `Err(RateLimited { retry_after })` | A counter is full at commit | `RATE_LIMITED` |
| `Err(Stale(_))` | New credential, expired offer or quote | STALE |
| `Err(Price(_))` | Admission refused, and no copy of the credential committed meanwhile | POLICY, UNDERPAID, `NOT_OFFERED`, `BAD_CREDENTIAL` |
| `Err(Plan(_))` | Offer outlives the record; bad rate config | POLICY; UNAVAILABLE |
| `Err(Store(_))` | Store unreachable | UNAVAILABLE, fail closed |

Offers are signed the same way: `UnsignedOffer::new(&fields, Some(&k_mac))`,
`signer.schnorr(u.message())`, `u.finish(&sig)`.

At start-up the gate loads its limits with `Limits::from_manifest`, which
refuses a `replay_window` below `pending_timeout + 120`, and calls
`limits.check_offer_lifetime(longest_offer_lifetime)` (ERRATA N3b-21).

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
- **Only bnap-core makes a `CommitPlan`**: its fields are private and its
  constructor is crate-private, so no plug can choose a `ReplayKey` or name
  a use ID in another scheme's space, and no gate can commit a request
  `process` did not look up and price.
- **One entry point, replay detection first** (re-cut, N3b-23).
  `outcome::process` computes the `ReplayKey` without an admission, looks
  up `outcome[rk]` and classifies a known credential before any pricing;
  only a new credential is admitted and committed. The earlier flow (admit,
  then build the plan from the admission, then commit) priced a replay
  again against counters its own commit had consumed.
- **The refund basis is fixed at commit** (N3b-26). The outcome record
  keeps the FAILED refund cap (`Admission::settle(Status::Failed, 0)`) and
  the entry's unit; `Recorded::refund_cap` returns it, so the refund of a
  timed-out outcome needs no admission and can only return what the commit
  consumed, whatever the replaying request presents.
- **A record outlives its offer** (N3b-25). The record keeps `keep_until =
  expires + 60`, and `purge` never deletes a record until `keep_until +
  60 < now`, whatever window it is given; a fresh commit on an expired
  offer is STALE. Together they stop a credential without single uses from
  being admitted again after a sweep ran with a shorter `replay_window`
  than the commit saw, or on a request whose clock reads up to a clock
  skew behind the sweep's.
- **A late settle loses to the timeout in the store** (N3b-24).
  `UseStore::settle` takes `pending_timeout`; a settle with `settled_at >
  created + pending_timeout` times the outcome out in the same transaction
  and returns `AlreadySettled`, so the answer never depends on when the
  sweep runs.
- **Sealed signer messages.** `Signer::schnorr` takes `&CoreMessage`, which
  has no public constructor; `UnsignedOffer` and `UnsignedResponse` are the
  only sources, and their `finish` checks the signature under the object's
  own key and re-parses the object. A compile_fail doctest in each crate
  shows that neither a `CoreMessage` literal nor raw bytes compile.
- **`CappedSigner` has no message signing at all.** Schemes get only it, so
  a scheme can never get an offer or a receipt signed, even though
  `UnsignedResponse` is public (it has no public constructor: only
  `Recorded::unsigned_receipt` makes one). Its verify-only view signs
  nothing.
- **The change cap is a budget for one settlement, and the outcome's
  value a total kept in the store.** Three checks, in this order, before
  any output is signed:
  1. In process, `for_change` makes one `Budget` (an `AtomicU64` of what
     is left): every `blind_sign` takes its outputs' sum out of it with a
     compare-and-swap, clones share it, a sum that overflows is above any
     cap, and the `SettleGuard` the gate holds closes it when `settle`
     returns, so a kept clone signs nothing.
  2. In the use store (N3b-29): `blind_sign` reserves the outputs with
     `outcome::reserve_change` in `outcome[rk]`, one transaction: one
     running total per `ReplayKey` across the OK change and every FAILED
     refund, each distinct output (keyset, amount, `B'`) once, so a
     deterministic settle that runs again signs the same notes for
     nothing, bounded by the smallest of the call's cap, the record's
     refund cap (the admitted value) and the first OK cap. The store is
     durable and shared by every gate instance, so this is the bound that
     holds across signer restarts, gate restarts and signer instances.
     An unreachable store signs nothing; an outcome without a record
     (purged) is refused. New outputs are taken only before the result
     they pay is recorded: while PENDING, or for a timed-out outcome's
     refund while it is due (`Reserve::Settled` otherwise; outputs reserved
     before may be signed again). And an OK settle is refused while more
     change is reserved than it leaves (`SettleError::ChangeOverCap`), so
     minted and charged together never pass the value.
  3. At the signer, every call carries a `ChangeLimit` (`ReplayKey`,
     status, unit, cap, `keep_until`); `ChangeLedger` keeps the same total
     in the signer's memory and pins the first cap each status is named
     with (ERRATA N3b-16). It is a second line: a restart or a second
     signer instance starts it from 0.

  A call that fails after step 1 keeps its share spent, and one that
  fails after step 2 keeps its reservation, since the signer may have
  signed. So at most the outcome's value is ever signed for it, change
  and refunds together, whatever process signed. The signer also refuses
  a keyset that is not in the limit's unit.
- **An honest refund is a superset of the change** (N3b-16). `bnap:notes`
  signs `outputs` on OK and `outputs` with `refund_outputs` on FAILED, so
  when a late OK settle signed the change before the timeout won, the
  refund re-signs those outputs for nothing and adds only the refund
  outputs: the client is paid in full, and a scheme that keeps its change
  signatures to return them with the refund gets nothing extra signed.
- **`ChangeCap` is sealed, and bound to one outcome.** `Admission` and
  `AdmittedPay` have private fields and only `pricing::admit` makes them
  (a compile_fail doctest shows an `Admission` literal does not compile),
  and `Admission::settle` returns a pure `Charge` that grants nothing. A
  `ChangeCap` is made only by `Pending::charge` (from the admission the
  commit was priced with) and `Recorded::refund_cap` (from the cap the
  commit recorded), and carries that outcome's `ReplayKey`, the entry's
  unit, the settlement's status and how long the outcome's record is
  kept (`keep_until`). `CappedSigner::for_change` takes the cap and the
  use store, never a `ReplayKey`, so a budget and its store reservation
  are always counted against the outcome the cap was computed for.
- **A note is named by its secret** (N3b-28). `Signer::verify_unblinded`
  takes the note's secret, computes `Y = hash_to_curve(secret)` itself
  (NUT-00, `bnap_core::note`) and returns the `Y` it checked; the capped
  view derives `Y` too and refuses a signer answer naming another point.
  From one note `(Y, C)`, every multiple `(m·Y, m·C)` passes a check of
  `C = k·y` for a caller-chosen `y`, so a scheme that names `y` could make
  one note count many times.
- **Every store write is sealed.** `UseStore::settle`, `expire_pending`,
  `record_refund` and `purge` take `SettleRequest`, `SweepWindow` and
  `RefundRequest`: private fields, getters for store implementers,
  constructors private to bnap-core. A `Settlement` has private fields and
  carries the `ReplayKey` of the `OutcomeCharge` it was built from;
  `outcome::settle` refuses one made for another outcome.
- **Only an `atomic` scheme gets a change budget.** The cap is
  `value - charged` when the scheme's registered refund property, which
  the gate passes in `PayValue.refund`, is `atomic`, and 0 for `none` and
  `out-of-band`, for change and refund alike: a `none` scheme keeps the
  excess (section 7, overpayment), and an `out-of-band` scheme refunds by
  its own means, never also in operator notes (ERRATA N3b-20).
- **Value is what operator-trusted plugs confirmed.** `admit` counts
  `min(scheme claim, backing)` where backing is the rails' confirmed
  amounts and the notes the signer's verify-only view accepted, each
  counted once (ERRATA N3b-15). `Backing` has public fields: the gate,
  which is trusted, builds it from `RailPayment::backing` and
  `CappedSigner::notes`; schemes never see `AdmitInput`. Every backing
  payment and note is a single use in the commit plan, so a scheme cannot
  count a payment or a note it does not let the socket consume.
- **A note is the operator's, not the scheme's.** A backing note is
  consumed under `H_"bnap/note"(Y)`, which does not depend on the scheme,
  the way a `RailId` does not: every value scheme on a gate checks notes
  through the same signer and keysets, so a note admitted under
  `bnap:notes` is SPENT under a Cashu adapter and the other way round
  (ERRATA N3b-19). The scheme's own `UseId`s for the note stay singles.
- **The admission binds the commit.** Inside `process`, the plan is
  completed from the `Admission` (its quota counter and backing), so a
  request priced at 0 by a quota is never committed without consuming the
  quota.
- **No receipt before the refund.** `Recorded::receipt` returns `None`
  for a timed-out outcome whose refund is not recorded (`refund_recorded`),
  on both refund paths (ERRATA N3b-17). The free `receipt` function is
  private, and so is every way to sign Response fields:
  `UnsignedResponse::new` and `ResponseFields::sign` / `sign_with_limit`
  are `pub(crate)` (tests reach them through `test_support`), so
  `Recorded::unsigned_receipt` is the only way a gate gets a receipt
  signed, and it makes none while the outcome is PENDING or its refund is
  due (6.4).
- **No signer work without value** (N3b-27). `CappedSigner::blind_sign`
  and `ChangeLedger::reserve` refuse an empty batch and any output of
  amount 0 before the budget or the total is touched.
- **The manifest is I-JSON** (N3a-13, updated). A member named twice at any
  depth is `ManifestError::DuplicateMember`; `manifest::parse_strict` is
  public for other JCS-hashed JSON.
- **The store contract is tested through the trait, concurrently on every
  money-path write.** `test_support::conformance` runs the `logic` rules
  against any `UseStore`, one call at a time and concurrently: `THREADS`
  (8) calls behind a barrier, `ROUNDS` (10) rounds per scenario, on
  commits of one plan, commits sharing a single, commits against one
  counter, settles racing the timeout on an outcome that shares its rate
  counter with an OK one (roles rotated each round), refunds of one
  timed-out outcome, and change reservations racing settles, or sweeps
  (alternate rounds), on one record. A store that splits any one of commit, settle, timeout,
  refund or reservation into a snapshot decision and a later write fails
  the scenario that covers it (`TwoStep` in the module's tests).
- **`Verified.rail_ids` are rail references** (`RailRef { kind, reference }`)
  that the rail confirms, per draft-00 6.1 and ERRATA row 19; the field
  keeps the overview's name. `Verified` adds `quota_id`, the local ID of
  the registry's `quota_id` identity.
- **`UseModel::Rate { k, epoch }`**: the registry says only `rate`, so `k`
  and `epoch` come from the gate's configuration.
- **Settlement charges**: OK non-metered is the admitted price; OK metered
  is `min(price(⌈units × rate / 1000⌉), price(amount))` in 128 bits under
  the admission's decision (no second quota use); FAILED is 0. The cap is
  `value - charged` for an `atomic` scheme (the whole value on FAILED) and
  0 otherwise. "Value" is always the admitted `min(claimed, backing)`.
  Overpayment is returned only by an `atomic` scheme, up to the cap; any
  other scheme keeps it.
- **The record window has a floor.** `Limits::from_manifest` refuses a
  `replay_window` below `pending_timeout + REFUND_MARGIN` (120 s, two
  clock skews), and the state machine and the sweep use
  `Limits::record_window()`, which applies the same floor to limits built
  by hand, so a crash-orphaned PENDING outcome always has time to be
  replayed and refunded after its timeout (ERRATA N3b-21).
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
| N3b-16 | 6.4, 7, overview signer | The overview's `blind_sign(.., cap)` takes a per-call cap with no settlement identity, so neither the scheme host nor an out-of-process signer can bound a scheme that calls it repeatedly | Each call names its settlement (`ChangeLimit`: `ReplayKey`, status, unit, cap) and the signer keeps **one running total per `ReplayKey`**, across the late OK settle and the FAILED refund of a timed-out outcome, counting each distinct output once across both, each call bounded by the first cap named for its status. So at most `value` is ever signed per `ReplayKey`. The earlier per-status totals let a hostile atomic scheme keep its change signatures and return them inside the refund's `scheme_result` (`value - charged` plus `value` signed). An honest refund is a superset of the change (`bnap:notes` FAILED signs `outputs` and `refund_outputs`), so it re-signs the change for nothing and is paid in full. Owner to confirm: schemes MUST make the refund a superset of the change |
| N3b-17 | 6.4 Replay | A timed-out outcome whose scheme has nothing to refund leaves `scheme_result` empty, so "refund recorded" cannot be read from `scheme_result` | `OutcomeRecord.refund_recorded` marks it; `record_refund` takes `Option<&[u8]>`; no receipt is made while a refund is due |
| N3b-18 | 6.4, 8.1 `replayed` | The late action whose settle lost to the timeout answers its own request from the recorded FAILED outcome | `replayed` is false: the Response answers the request that ran the action, not a replay |
| N3b-19 | 6.1, 6.2; N3b-15 | Notes verified by the shared signer are single-use across schemes. Draft-00 scopes every `UseId` by scheme, so a note the operator's signer verified, carried by two value schemes (`bnap:notes` and a Cashu NUT-24 adapter), has two `UseId`s and was admitted once per scheme | A backing note commits under `H_"bnap/note"(Y)` (Y the 33-byte point), which does not depend on the scheme, like a `RailId`; the scheme's own `UseId`s stay singles too. One note admits one action whichever scheme carries it |
| N3b-20 | 6.4 Settle, 7 Overpayment | Draft-00 says the value scheme refunds "as its registered refund property allows" and that only "a scheme that can return change" returns overpayment, but not whether the socket or the scheme enforces this | The socket enforces it: the gate passes the registered `refund` (unknown counts as `none`), and the change cap is `value - charged` only for `atomic`, 0 for `none` and `out-of-band`, for change and refund alike. An `upto` scheme in a metered offer settles the lower amount itself |
| N3b-21 | 6.4, 9.1 `limits` | Draft-00 states no relation between `replay_window` and `pending_timeout`. With `replay_window <= pending_timeout`, a crash-orphaned PENDING outcome is timed out by the first late replay, which then finds it past its window and answers SPENT; the sweep deletes the refund with the record | `Limits::from_manifest` refuses `replay_window < pending_timeout + 120` (two clock skews); `check_offer_lifetime(L)` requires `replay_window >= pending_timeout + 120 + L` so every replay an offer allows finds its record; `record_window()` floors hand-built limits the same way |
| N3b-22 | 4.4 step 4, 6.4 | A replay is checked like any credential, so once its offer has expired it is STALE before it reaches the store. An exact-scope offer that lives less than `pending_timeout` past the commit therefore leaves a crash-orphaned outcome's refund uncollectable, whatever the limits | **Core side done, gate decision open.** `process` looks up `outcome[rk]` before it checks expiry, answers a known credential from its outcome, and refuses a fresh commit on an expired offer or quote with STALE. A gate that takes the first option of the owner decision runs 4.4 as usual and, on STALE only, still calls `process` for an authentic offer: it answers replays and never commits. Owner decision: that, or require offers to outlive `pending_timeout`. The gate node owns 4.4 |
| N3b-23 | 3, 7 vs 6.4 | Section 3's flow and section 7 price before commit (step 3 "price ... check value", step 4 "commit"), while 6.4 promises an OK or FAILED outcome inside `replay_window` its stored answer and makes replaying how a client fetches a missed receipt. Read literally, a quota-priced credential whose own commit filled the quota is refused on replay (UNDERPAID at 2⁶⁴ − 1 without pay, or at the entry amount), its recorded change is unreachable, and a crash-orphaned outcome's refund waits for a sweep | **Not the literal order.** `outcome::process` computes the `ReplayKey` (which needs no price), looks up `outcome[rk]` and classifies a known credential (replay, PENDING, SPENT) before any pricing; only a new credential is priced and committed. Owner decision: reword section 3 and 6.4 ("Before commit") to say replay detection precedes pricing |
| N3b-24 | 6.4 Timeout | Whether the late action's settle can still win when no sweep or replay has timed the outcome out | No: the store's settle refuses a settle with `settled_at > created + pending_timeout` and times the outcome out in the same transaction, so the late action takes the refund path. Extends N3b-7 and N3b-13: no answer depends on sweep timing |
| N3b-25 | 6.1, 12 "Retention" | 6.1's `expires + 60 <= now + replay_window` is checked at commit with the commit's limits, but purge runs later, possibly with other limits (a manifest that lowered `replay_window`). The probe: a reusable-only credential was purged and admitted again as New while its offer was valid | The record keeps `keep_until = expires + 60` and purge never deletes it until `keep_until + 60 < now`; a fresh commit on an expired offer is STALE. The extra clock skew covers a request whose clock reads up to 60 s behind the sweep's (taken before a slow check, or on another gate instance), so a purged credential can never be admitted again |
| N3b-26 | 6.4, 7 | What the refund of a timed-out outcome is computed from once its replay is no longer priced | From the commit: the record keeps the FAILED refund cap (the admitted value for an `atomic` scheme, 0 otherwise) and the entry's unit. Backing a replay presents beyond what the commit consumed (6.1 keeps backing notes out of the `ReplayKey`) is neither consumed nor refunded |
| N3b-27 | overview signer, 6.4 | Blinded outputs of amount 0, and empty batches, carry no value but are signer work without bound under any cap | Refused by `CappedSigner::blind_sign` before the budget is touched and by `ChangeLedger::reserve`; the `Signer` trait states the rule |
| N3b-28 | overview signer, 6.1, 12 "Untrusted schemes", `schemes/bnap-notes.md` | The overview's `verify_unblinded(ks, y, c)` takes the point `Y` from the caller. From one note `(Y, C = k·Y)`, every multiple `(m·Y, m·C)` passes `C == k·y`, each with its own `note_id`, so a broken scheme (one that reads `Y` off the wire) makes one note count many times, against 12's "a broken scheme cannot make one payment count twice" | **Not the overview's signature.** `verify_unblinded(keyset, unit, amount, secret, c) -> Option<Point>`: the signer computes `Y = hash_to_curve(secret)` (NUT-00) and returns the `Y` it checked; the capped view derives it too and keeps only that `Y`. The overview's signer trait needs the same change |

| N3b-29 | overview signer, 6.4, 12 "Durability" | The overview puts the change total in the signer, and nothing says it must survive a restart or be shared between signer instances. A scheme that keeps its signatures and fails every settle leaves no refund recorded, so each replay opens a new refund budget of the whole value; a restarted signer, or a second one on a shared store, signs it again (142 sat for 96 paid after one restart, 366 after three) | **Not in the signer alone.** The use store keeps each outcome's change ledger in `outcome[rk]`: `UseStore::reserve_change`, called by the gate's `CappedSigner` before every signer call, in one durable transaction, bounds change and every refund of one `ReplayKey` together at the admitted value, across restarts and instances, for as long as the record exists. The signer's own total stays as a second line, kept at least until `ChangeLimit::keep_until`. The overview's signer and store traits need the same change |

### Tests, part B

- `src/outcome/tests.rs` (state machine, `MemoryStore`), every request
  through `process`: a concurrent double spend of one note by 16
  credentials (exactly one wins, one `used` entry, one outcome); 12
  concurrent retries of one credential (one New, the rest PENDING); replay
  returns the recorded outcome with `replayed`, the original `settled_at`
  and the new Digest, and writes nothing; no status flip after settlement;
  same use IDs under another `ReplayKey` are SPENT, including a body
  altered on the path; a replay names only its own record (a request
  sharing one single with a commit is SPENT and consumes nothing; a replay
  presenting extra backing is answered from the record and refunds the
  committed 64 sat, not 164); one Lightning payment through L402 and MPP is
  a conflict; `RailId`s stay single under reusable and rate models; an
  abort consumes nothing; rate counters, `retry_after` and give-back on
  FAILED; FAILED keeps single uses spent; pending timeout, late settle
  refused, no receipt before the refund, the refund recorded once; a
  replay past the timeout times out at once; replay window edge, purge,
  then STALE for the expired offer and SPENT for its note; PENDING never
  purged; the 6.1 rule; reusable and duplicate IDs in the `ReplayKey`; a
  store outage fails closed before pricing; a binding change on retry
  keeps the `ReplayKey`; the checker's three MEDIUM probes (an
  attestation-only replay, a lost response with 10 sat of recorded change,
  a crash-orphaned refund, each under a quota its own commit filled); a
  stale quota read never admits past the limit (`StaleReads`, a store whose
  pricing reads always see room); 16 concurrent quota admissions under a
  limit of 3 give exactly 3; 12 concurrent replays after a crash refund
  once; settle against the timeout, 20 rounds of 8 threads, one transition
  and at most one give-back; a record kept while its offer can be presented
  (the sweep on a shorter window purges nothing, the gate replays, never
  New, then STALE after `keep_until`); STALE for a new credential on an
  expired offer or quote, a replay still answered; every backing payment
  and note consumed; one signer-verified note under `bnap:notes` and
  `cashu:nut24` in both orders; a refund with nothing to return; a late
  settle answering from the FAILED record; a settle past the timeout with
  no sweep (the checker's LOW probe) and one at the deadline; the limits
  rules (window floor, offer lifetime, minimum window, hand-built limits);
  a copy of a quota-priced credential that missed its own commit answered
  PENDING, with and without pay (one interleaving, through a store whose
  lookup misses once), and the checker's barrier probe (24 copies, 20
  rounds, 300 us per store call: one New, the rest PENDING); a request
  lagging the first purging sweep by 1, 30 or 60 s answered from the
  record or STALE, never New; a settlement charged for one outcome refused
  on another (`WrongOutcome`); change and refund reserving one total
  through the outcome, a store reloaded after a restart still refusing
  fresh refund outputs for the whole value (N3b-29).
- `src/note.rs`: `hash_to_curve` against the three NUT-00 vectors.
- `src/test_support.rs`: the conformance suite passes on `MemoryStore`;
  `TwoStep`, a store that splits one write (commit, settle, timeout,
  refund or change reservation) into a snapshot decision and a later
  write, passes every scenario one call at a time and fails the
  concurrent scenario that covers its split, and `run` (stressed 25 and
  20 times while writing them, never missed); purge keeps a record at
  `keep_until + 60` and deletes it at `keep_until + 61`; the change
  ledger's rules (one total across OK and FAILED, dedupe, the first OK
  cap pinned, no cap above the value, `NoValue`, `Unknown`, kept through
  settle, timeout and refund, gone with the record).
- Doctests, all compile_fail: no `CoreMessage` from raw bytes (both
  crates), no `Admission` literal, no `Pending` literal, no
  `CommitPlan::build`, no `Settlement` literal (E0451), no
  `SettleRequest::new`, `RefundRequest::new`, `SweepWindow::new`,
  `ChangeRequest::new` or `ChangeCap::new` outside bnap-core (E0624). Each was also compiled on its
  own to check that it fails for that reason.
- `src/manifest.rs` and `tests/negative.rs`: I-JSON, a member named twice
  at the top level, in `routes[0]`, in `routes[0].price`, in `keys[0]`, in
  arrays and with an escaped spelling, refused; equal names in different
  objects accepted.
- `tests/pricing.rs`: the price table (two 20% discounts give 36%, waive
  beats discount in either order, bearer attestations cannot waive or
  discount, rounding, the 10.3 example), admission rules, attestation-only
  offers, the no-pay bypass of N3b-1, quota order, room and epochs, the
  10.3 metered charge (340 sat, 1,340 sat of change), products beyond 2⁶⁴,
  overpayment, FAILED; caps by refund property (the review's L402 probe:
  1,000 sat backing on a 21 sat entry gives caps 0 on OK and FAILED for
  `none` and `out-of-band`, 979 and 1,000 for `atomic`), a metered `upto`
  entry without atomic refund, refund tokens; backing (the review's probe of 21 msat against a
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
- `bnap-plug/tests/plugs.rs` (the test signer checks notes with real
  secp256k1 BDHKE math, `C = k·hash_to_curve(secret)`): a scaled `(m·Y,
  m·C)` or negated note never verifies and one real note in five
  credentials admits one action, with a change cap of 29, never 979 (the
  checker's HIGH probe); a hostile atomic scheme that keeps its OK change
  signatures and returns them with the refund gets at most the value
  minted (96, not 142), after a late settle and after a slow action; an
  honest scheme whose refund re-signs its change is paid in full (96
  minted, and 46 on time); the ledger bounds change and refund of one
  `ReplayKey` together in either order and pins the first cap per
  status; the capped signer (over the cap, overflow,
  two calls whose sum exceeds the cap, 16 concurrent clones that sign 99
  of a 100 cap in 3 sat steps, a clone used after the guard closed, a
  guard dropped at once, a mismatched answer, 1,000 zero-amount outputs, a
  zero among valued outputs and an empty batch refused by the budget and
  by the ledger), the signer's running total
  per settlement (two budgets for one settlement, re-signing the same
  outputs, separate refund and outcome totals, a keyset in another unit),
  concurrent refunds of one outcome, the signer's total kept until
  `keep_until` plus a skew and the store refusing a fresh refund output
  after the signer forgot, the verify-only view keeping each
  accepted note once, a key-use-checking test signer, and the whole gate
  flow through `dyn` plugs and `process` (mock L402, MPP and notes
  schemes, a fake Lightning rail, the in-memory store): one payment under two schemes
  admits one action, the replay is re-signed with `replayed`, an
  underpaying rail reference (the review's probe), a payment in another
  unit, a payment that is not final, a notes claim above the verified
  notes, a greedy scheme that signs the cap twice and keeps its signer
  (the review's probe: 46 sat signed in all, the kept clone refused), an
  action that outlives the timeout answering FAILED with its refund, a
  action whose settle comes after the timeout with no sweep answering
  FAILED with its refund, a replay after a crash collecting the refund, an
  unpaid payment never
  reaching commit, an outage failing closed, one note under two value
  schemes (SPENT the second time, in both orders), an L402 payment of
  1,000 sat for a 21 sat entry that signs no change and no refund; a
  scheme that hoards its OK change and every FAILED refund and fails
  each settle, replayed across two signer instances on one store and
  across three signer restarts with the store reloaded each time,
  minting 78 sat (at most the 96 paid, and exactly what the store
  reserved; before the fix 174 and 366); plus a string carrier, judge
  decisions, budgets and scheme error codes.

#### Status at hand-off, part B (after the re-cut, repair round 2)

- `cargo-q nextest run -p bnap-core -p bnap-plug --features
  bnap-core/test-support`, and the same without the feature: 207 tests,
  207 passed (174 in `bnap-core`, 33 in `bnap-plug`).
- `cargo-q test --doc -p bnap-core -p bnap-plug`: 11 doctests pass, all
  compile_fail (listed under "Tests, part B").
- `cargo-q clippy -p bnap-core -p bnap-plug --all-targets --locked -- -D
  warnings`, with and without `--features bnap-core/test-support`: clean
  (pedantic included, toolchain 1.99.0).
- `RUSTDOCFLAGS="-D warnings" cargo-q doc -p bnap-core -p bnap-plug
  --no-deps --features bnap-core/test-support`: clean. `cargo-q fmt
  --check`: clean. `ops/leak-guard.sh`: clean. `Cargo.lock` unchanged
  (no new dependency: the plug tests reach secp256k1 through
  `bnap_core::secp256k1`).

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

### Repair round 2

A second non-author check failed part B with three findings. Each is fixed
in its own commit, with the review's probe as a test:

| Finding | Fix | Commit |
| --- | --- | --- |
| HIGH: one signer-verified note spent once per value scheme (backing consumed as `use_id(pay scheme, Y)`) | Backing notes commit under `H_"bnap/note"(Y)`, independent of the scheme (N3b-19) | `fix(core): spend a signer-verified note once across value schemes` |
| MEDIUM: change and refund caps ignore the registered refund property | `PayValue.refund`; cap is `value - charged` only for `atomic`, else 0 (N3b-20) | `fix(core): give a change cap only to schemes whose refund is atomic` |
| LOW: `replay_window <= pending_timeout` accepted, losing a crash-orphaned refund | `from_manifest` refuses it, `check_offer_lifetime`, `record_window` floor (N3b-21) | `fix(core): refuse limits whose replay window can lose a timed-out refund` |

### Re-cut (round 3)

A third non-author check failed part B with three findings, one of them a
design flaw (admission before replay detection), and a background security
review sent five findings with open leads. The design was re-cut instead
of patched (`outcome::process`, see "The process contract"). Each input
below has a test that fails before its fix and passes after, committed
with the fix; for an item an earlier round had already closed, the test
that proves it closed is named (written now if it was missing). Before the
re-cut, the checker's three MEDIUM probes were run against the old API and
answered `Underpaid { price: 18446744073709551615, value: 0 }`,
`Underpaid { price: 21, value: 10 }` and `Underpaid { price: 21, value:
10 }`; the purge probe (store lead a) answered `New` for the purged
credential.

| # | Input | Status | Test that proves it | Commit |
| --- | --- | --- | --- | --- |
| C1 | Checker, MEDIUM: admission (pricing) ran before replay detection, and re-read quota counters the original commit consumed, so a legitimate replay was mispriced or refused | Fixed by the re-cut: `ReplayKey` before pricing, `outcome[rk]` classified before any admission, one `process` entry point, `CommitPlan::build` crate-private, refund cap recorded at commit (N3b-23, N3b-26) | `outcome::tests::a_quota_priced_attestation_replays_after_its_commit_filled_the_quota`, `a_quota_priced_payment_replays_its_recorded_change`, `a_quota_priced_payment_collects_its_refund_after_a_crash` | `544ac2c` |
| C2 | Checker, LOW: a PENDING outcome past `created + pending_timeout` could still settle OK if no sweep or replay ran | Fixed in the store: `settle` takes `pending_timeout` and times the outcome out in the same transaction (N3b-24) | `outcome::tests::a_settle_after_the_pending_timeout_times_the_outcome_out`; `plugs::an_action_that_settles_after_the_timeout_loses_to_it_without_a_sweep`; conformance `settle_changes_the_status_once` | `7e291a8` |
| C3 | Checker, LOW: zero-amount blinded outputs passed the budget and the ledger | Fixed: refused, with empty batches, before the budget and in `ChangeLedger::reserve` (N3b-27) | `plugs::zero_amount_outputs_and_empty_batches_are_refused` | `ea6b760` |
| S1 | Security 1: `SignedManifest::parse` accepted duplicate member names (last wins), a parser differential on a signed document | Fixed: I-JSON at every depth, `ManifestError::DuplicateMember`; `parse_strict` public for other JCS inputs (N3a-13) | `negative::manifest_members_named_twice_are_refused`, `manifest::tests::strict_json_refuses_names_repeated_at_any_depth` | `66a911d`, `3f551cb` |
| S2a | Security 2, lead a: pricing reads quota counters separately; can a stale read admit past the limit? | Closed. `logic::commit` already re-checked every counter in the commit transaction; `process` now prices only new credentials and always commits the chosen counter, and the trait documents the serializable requirement | `outcome::tests::a_stale_quota_read_never_admits_past_the_limit`, `concurrent_quota_admissions_never_exceed_the_limit` (16 at once, limit 3, exactly 3) | `544ac2c` |
| S2b | Security 2, lead b: concurrent replays of a timed-out outcome must not each refund or run the action | Closed. The outcome times out once, `record_refund` is first-write-wins, the signer ledger bounds the refund per `ReplayKey`; a replay is never priced, so a quota-priced one is no longer refused | `outcome::tests::concurrent_replays_after_a_crash_refund_once`; `plugs::concurrent_refunds_of_one_outcome_sign_its_value_once` | `544ac2c` |
| S2c | Security 2, lead c: re-admission after purge for credentials without single uses | Fixed: `keep_until` in the record, purge never deletes before it; a fresh commit on an expired offer is STALE (N3b-25) | `outcome::tests::a_record_is_kept_while_its_offer_can_be_presented`; conformance `purge_keeps_what_must_stay` | `544ac2c` |
| S2d | Security 2, lead d: settle against `expire_pending` on one `ReplayKey` | Closed. Both are conditional updates from PENDING in one store transaction, and a late settle now loses to the timeout (C2) | `outcome::tests::settle_and_the_timeout_race_to_one_transition` (20 rounds, 8 threads, one transition, at most one give-back) | `544ac2c` |
| S3 | Security 3: `CappedSigner` cap per call, not cumulative | Closed in repair round 1: a shared `AtomicU64` budget taken with compare-and-swap, `SettleGuard`, and the signer's per-settlement `ChangeLedger` | `plugs::two_calls_whose_sum_exceeds_the_cap_are_refused`, `concurrent_clones_never_exceed_the_cap_in_total`, `a_clone_used_after_settle_returns_is_refused`, `the_signer_keeps_a_running_total_per_settlement` | `ccdfb83` |
| S4 | Security 4: `confirm_rail_id` ignored the rail-confirmed amount, unit and finality | Closed in repair round 1: `RailPayment { rail_id, amount, unit }`, only `Paid` confirms, admission counts `min(claim, backing)` and refuses a unit that does not convert | `plugs::the_rail_supplies_the_rail_id`, `an_underpaying_rail_reference_is_underpaid`, `a_payment_in_another_unit_is_refused`, `a_payment_that_is_not_final_never_reaches_commit`; the backing tests in `tests/pricing.rs` | `cc41095` |
| S5a | Security 5, lead a: re-admission after purge (store level) | Fixed with S2c, in the store itself: `logic::purge` checks `keep_until` whatever window the caller computed | as S2c | `544ac2c` |
| S5b | Security 5, lead b: a replay is answered without checking that the request's singles map to `rk` | Closed by construction: the `ReplayKey` covers every `UseId` and `RailId`; backing outside it is never consumed or refunded on a replay (N3b-26) | `outcome::tests::a_replay_names_only_its_own_record` | `544ac2c` |
| S5c | Security 5, lead c: counters checked then incremented outside one atomic step in non-logic stores | Documented on `UseStore` (serializable means one atomic step per method) and tested: `test_support::conformance`, which a two-step store fails. Wiring it into `bnap-store-tests` is **deferred** to the store node, which owns that stub crate | `test_support::tests::the_memory_store_conforms`, `a_store_that_checks_and_counts_in_two_steps_fails_conformance` | `9b1ee98` |
| S5d | Security 5, lead d: `RailId`s must be single even when the scheme's model is rate or reusable | Closed: `Uses::collect` adds every `RailId` to the singles whatever the model | `outcome::tests::rail_ids_are_single_whatever_the_scheme_model` | `544ac2c` |

### Re-cut, repair round 1

Non-author checkers failed the re-cut with five findings. Each has a test
that failed before its fix (run and seen failing, with the numbers below)
and passes after, committed with the fix.

| # | Finding | Fix | Test that proves it | Commit |
| --- | --- | --- | --- | --- |
| R1 | HIGH, money path: `Signer::verify_unblinded` took `Y` from the scheme, so a scaled pair `(m·Y, m·C)` of one real note passed `C == k·y` with a new `note_id` each time. With real BDHKE math one 50 sat note admitted 5 actions out of 5 | The scheme passes the note's secret; the signer computes `Y = hash_to_curve(secret)` (NUT-00, new `bnap_core::note`) and returns it; the capped view derives `Y` itself, refuses a signer answer naming another point, and tallies only that `Y` (N3b-28) | `plugs::a_scaled_or_negated_note_never_counts_and_one_note_admits_one_action` (before: the probe counted 5 New for one note); `note::tests::hash_to_curve_matches_the_nut_00_vectors` | `fe65a17` |
| R2 | MEDIUM-LOW: TOCTOU between the `outcome[rk]` lookup and admission; a copy of a quota-priced credential that raced its own commit answered UNDERPAID instead of PENDING | When the fresh path fails before the commit, `process` reads `outcome[rk]` again and classifies a record it finds | `outcome::tests::a_copy_that_missed_the_record_is_pending_not_underpaid` (before: `Underpaid { price: 21, value: 10 }`), `concurrent_copies_of_one_quota_priced_credential_are_never_underpaid` (before: 11 of 24 copies UNDERPAID in round 1) | `a3633e9` |
| R3 | LOW: purge deleted a record as soon as `keep_until < now`, and a fresh commit is STALE only when `now > keep_until`, so a request whose clock lagged the sweep's by 1 s was admitted again as New | Purge only when `keep_until + 60 < now` (N3b-25); docs, the conformance scenario and the retention test pin the new edge | `outcome::tests::a_lagging_clock_never_readmits_a_purged_credential` (before: the sweep at `keep_until + 1` purged 1); conformance `purge_keeps_what_must_stay` | `4e90acf` |
| R4 | LOW, API sealing: the store trait's writes took raw arguments, `Settlement` had public fields and any one settled any outcome, `record_refund(None)` could skip the refund, and `for_change` paired a cap with any `ReplayKey` | `SettleRequest`, `RefundRequest`, `SweepWindow` sealed; `Settlement` private and bound to its `OutcomeCharge`'s `ReplayKey` (`WrongOutcome` otherwise); `ChangeCap` carries its `ReplayKey` and `for_change` takes only the cap; `Charge` is pure pricing. `record_refund` cannot see the plug call, so its docs say the gate MUST NOT skip the refund settle (no longer "cannot") | `outcome::tests::a_settlement_settles_only_the_outcome_it_was_charged_for` (before: the other outcome settled OK); compile_fail doctests in `store` and `bnap_plug::signer` | `0b7aa89` |
| R5 | A hostile atomic value scheme got more than the value signed: when an outcome opened an OK change budget and then ended FAILED, it signed both budgets in full and returned the kept change inside the refund's `scheme_result` | `ChangeLedger` keeps one total per `ReplayKey` across both statuses, each distinct output once, each call bounded by its status's first cap; an honest refund is a superset of the change (N3b-16) | `plugs::a_hostile_atomic_scheme_never_gets_more_than_the_value_signed` (before: 142 sat minted for 96 paid), `the_ledger_bounds_change_and_refund_together`; `an_honest_refund_that_re_signs_its_change_is_paid_in_full` keeps the honest path whole | `5775363` |

### Re-cut, repair round 2

Non-author checkers failed the re-cut again with two findings. Each has a
test that failed before its fix (run and seen failing, with the numbers
below) and passes after, committed with the fix.

| # | Finding | Fix | Test that proves it | Commit |
| --- | --- | --- | --- | --- |
| R6 | LOW, test coverage: the conformance suite meant to certify any `UseStore` ran only commit counters concurrently. The checker's `ReadThenWrite` store (settle, `expire_pending` and `record_refund` deciding on a snapshot, writing in a second step) passed `run`, while under 8 tasks several settles won one outcome, OK records had their counter given back, and 7 refunds were each recorded and returned | `conformance::run` gains `settle_and_timeout_race_to_one_transition` (8 threads per round, settles OK and FAILED at the deadline against sweeps past it, roles rotated each round, on an outcome sharing its rate counter with an OK one: one transition, the winner's record, the counter given back once on FAILED and never on OK), `concurrent_refunds_record_once` (every caller gets the stored record), `concurrent_commits_of_one_plan_make_one_outcome` and `concurrent_commits_sharing_a_single_spend_it_once`. The `UseStore` docs say the conformance covers settle, timeout and refund concurrency | `test_support::tests::a_store_that_settles_in_two_steps_fails_conformance`, `..._times_out_...`, `..._records_refunds_...` (before: `run` passed all three stores), `a_store_that_commits_in_two_steps_fails_the_commit_races`, `a_two_step_store_passes_every_scenario_one_call_at_a_time` | `6bbafe1` |
| R7 | A hostile atomic scheme with a colluding client got more than `value` signed for one outcome: the only bound across the OK change and the FAILED refunds was the signer's in-memory `ChangeLedger`, which a restart or a second signer instance resets, and a scheme that keeps its signatures and fails every settle leaves `needs_refund` true for the whole record window (checker: 142 sat minted for 96 paid after one restart, 384 across four lifetimes) | Option (a) of the finding: the ledger moved into the use store (N3b-29). `UseStore::reserve_change` keeps one total per `ReplayKey` in `outcome[rk]`, written in one durable transaction before any signature; `CappedSigner::for_change(inner, store, cap)` reserves before every signer call. `ChangeCap::keep_until` and `ChangeLimit::keep_until` (the earliest purge of the record: record window from commit, a skew past the offer's `keep_until`), `ChangeLedger::forget_expired(now)` replacing `forget`. Docs at `signer.rs` (the old in-memory safety claim) and here corrected | `plugs::a_hoarding_scheme_never_mints_more_than_the_value_across_signer_instances` (before: 174 sat minted for 96 paid), `..._across_signer_restarts` (store reloaded each restart; before: 366 after three restarts; both now 78, equal to what the store reserved); `outcome::tests::change_and_refund_reserve_one_total_through_the_outcome`; conformance `change_is_one_total_per_outcome`, `concurrent_reservations_keep_one_total` (`a_store_that_reserves_change_in_two_steps_fails_conformance`) | `750f59f` (core), `593d5b0` (plug) |

### Re-cut, repair round 3

Non-author checkers failed the re-cut a third time with four findings.
Each code finding has a test that failed before its fix (run and seen
failing, with the numbers below) and passes after, committed with the
fix.

| # | Finding | Fix | Test that proves it | Commit |
| --- | --- | --- | --- | --- |
| R8 | MEDIUM: any `ResponseFields` could be signed (`ResponseFields::sign`, or `UnsignedResponse::new` and the signer), so a gate could sign an OK receipt with change for an outcome the store still held as PENDING, or before a timed-out outcome's refund was recorded (6.4); the claims "every answer is built from a `Recorded`" held only for `Recorded::receipt` | `Recorded::unsigned_receipt` is the only public way to sign a Response, `None` while PENDING or a refund is due; `UnsignedResponse::new` is `pub(crate)`, `ResponseFields::sign` / `sign_with_limit` `pub(crate)` and test-only, re-exposed as `test_support::sign_response`, `sign_response_with_limit`, `unsigned_response` for the codec tests and vectors (their targets require `test-support`). Claims corrected here and in `outcome` | compile_fail doctests on `UnsignedResponse::new`, `ResponseFields::sign`, `sign_with_limit` (all three compile, so fail, with the old visibility); `outcome::tests::a_pending_or_refund_due_outcome_yields_no_unsigned_receipt` | `7842b9c` |
| R9 | LOW: `logic::reserve_change` ignored the record's status, so fresh outputs were reserved and signed after the settle (46 sat minted, the record's `scheme_result` None) or after another replay recorded the refund ("refund 10", then 86 more, 96 minted), against 6.4's "MUST NOT pay out anything beyond that recorded result" | New outputs only while PENDING, or for a FAILED reservation while the outcome `needs_refund`; otherwise `Reserve::Settled`, nothing written, which `CappedSigner` refuses before the signer. Re-signing reserved outputs stays allowed | `plugs::no_change_is_signed_after_the_settle_is_recorded`, `a_refund_cap_signs_nothing_after_the_refund_is_recorded` (both failed before); conformance `no_fresh_change_after_the_outcome_settles`, `no_fresh_change_after_a_racing_refund`, and the settle rounds of `concurrent_reservations_keep_one_total` (every settle returns the final record); the memory store fails conformance with the check removed | `397ead6` |
| R10 | LOW: a FAILED cap and an OK settle of one outcome were accepted together: 96 sat signed under the FAILED cap, then OK charged 50, minted plus charged above the value | `logic::settle` refuses an in-time OK settle, writing nothing, when `change_total > refund_cap - charged`: `Settle::ChangeOverCap`, `SettleError::ChangeOverCap` (UNAVAILABLE; the gate settles FAILED). Honest flows never meet it | `plugs::a_failed_cap_then_an_ok_settle_is_refused` (before: accepted, charged 50 with 96 minted); conformance `an_ok_settle_leaves_room_for_its_change` | `1fc77c0` |
| R11 | LOW, flaky self-test: when the sweeps timed the outcome out before a two-step settle took its snapshot, `concurrent_reservations_keep_one_total` let the Settle-split store pass (`a_store_that_reserves_change_in_two_steps_fails_conformance` failed about 1 in 15 suite runs) | Rounds alternate settles and sweeps against the reservations, never both, with the roles rotating between rounds of a kind; each round asserts exactly one transition. The negative test asserts detection over up to 8 attempts | `test_support::tests::a_store_that_reserves_change_in_two_steps_fails_conformance`. Per attempt, each split was detected 30 of 30 times. The core and plug suite ran 100 times with no failure while 331 runs of the concurrency tests (conformance, two-step negatives, outcome races) ran beside it, load average 11 to 17, also with no failure | `72c097d` |

### Changes to part A files

- `OfferFields::to_stream` and `ResponseFields::to_stream` are
  `pub(crate)` instead of private, so `sign` can serialize without a local
  key. No behaviour change.
- Re-cut, repair round 3: `ResponseFields::sign` and `sign_with_limit`
  are `pub(crate)` and exist only in test builds, and
  `UnsignedResponse::new` is `pub(crate)` (R8). `tests/vectors.rs`,
  `tests/negative.rs`, `tests/props.rs` and `tests/sign.rs` sign through
  `test_support` and require the `test-support` feature. **API change**.
- `lib.rs`: the new modules and re-exports. `Cargo.toml`: `async-trait`
  (workspace dependency) and the `test-support` feature.
- `manifest.rs` (re-cut): the document is parsed as I-JSON
  (`parse_strict`, now public), and `ManifestError` gains
  `DuplicateMember`. `tests/negative.rs` gains the duplicate-member test.
- `limits.rs` (repair round 2): `Limits::from_manifest` returns
  `Result<Limits, LimitsError>` and refuses a `replay_window` below
  `pending_timeout + REFUND_MARGIN`; new `REFUND_MARGIN`, `LimitsError`,
  `min_replay_window`, `validate`, `check_offer_lifetime` and
  `record_window`. `tests/vectors.rs` and `tests/negative.rs` unwrap the
  result. **API change** for any caller of `from_manifest`.

### Merge notes, part B

- `Cargo.lock` gains `async-trait` and `bnap-plug`'s edges; regenerate it on
  conflict. No workspace dependency was added.
- `bnap-plug` depends on `bnap-core` by path (`../bnap-core`); no crate
  declared an internal dependency before, so there was no pattern to
  follow.
- Downstream crates that want `MemoryStore` or the conformance suite add
  `bnap-core = { path = "../bnap-core", features = ["test-support"] }` to
  their dev-dependencies.
- **API changes in the re-cut's repair round 3**:
  `UnsignedResponse::new`, `ResponseFields::sign` and `sign_with_limit`
  are no longer public; sign through `Recorded::unsigned_receipt`, or in
  tests through `test_support::{sign_response, sign_response_with_limit,
  unsigned_response}` (the `negative`, `props`, `sign` and `vectors` test
  targets of bnap-core now require the `test-support` feature). `Reserve`
  gains `Settled`; `Settle` and `SettleError` gain `ChangeOverCap { total,
  cap }`. `conformance` gains `no_fresh_change_after_the_outcome_settles`,
  `no_fresh_change_after_a_racing_refund` and
  `an_ok_settle_leaves_room_for_its_change`.
- **API changes in the re-cut's repair round 2**: `UseStore` has a new
  required method, `reserve_change(&ChangeRequest)`, with
  `logic::reserve_change` for `UseTable` stores; `OutcomeRecord` gains
  `change_total`, `change_cap_ok` and `change_outputs`;
  `CappedSigner::for_change` takes the use store
  (`for_change(inner, store, &cap)`); `ChangeLimit` gains `keep_until`;
  `ChangeLedger::forget(rk)` is now `forget_expired(now)`; `ChangeCap`
  gains `keep_until()`. New: `outcome::reserve_change`, `ChangeOutput`,
  `ChangeRequest`, `Reserve`, `MemoryStore::reloaded`,
  `conformance::{THREADS, ROUNDS}` and six scenarios.
- **API changes in the re-cut's repair round 1**: `Signer::verify_unblinded`
  and `CappedSigner::verify_unblinded` take the note's secret instead of
  `Y` and return `Option<Point>`; `ChangeLedger::total` takes only the
  `ReplayKey` and the signer keeps one total per outcome;
  `CappedSigner::for_change(inner, &ChangeCap)` takes no `ReplayKey`;
  `Pending::charge` returns `OutcomeCharge`; `pricing::Charge` fields are
  getters and `cap` is `change()`; `Settlement` fields are private and
  `Settlement::new` takes an `OutcomeCharge`; `UseStore::settle`,
  `expire_pending`, `record_refund` and `purge` take `SettleRequest`,
  `SweepWindow` and `RefundRequest`; `SettleError` gains `WrongOutcome`.
- **API changes in the re-cut** for anyone who used the round 2 API:
  `outcome::commit`, `outcome::admit`, `CommitError`, `AdmitError`,
  `store::PlanInput` and the public `CommitPlan::build` are gone; call
  `outcome::process` with an `outcome::Request`. `settle` takes `&Pending`
  and `&Limits` and returns `Recorded`; `SettleError::AlreadySettled`
  carries a `Recorded`; `record_refund` takes `&Recorded`; receipts come
  from `Recorded::receipt`. `UseStore::settle` takes `pending_timeout` and
  `UseStore::purge` takes `now`; `OutcomeRecord` gains `keep_until`,
  `refund_cap` and `unit`, and `OutcomeRecord::pending` takes the plan.
  No crate outside this branch used any of them.

### Known gaps and notes for downstream nodes

- **Stores** (`bnap-store-sqlite`, `bnap-store-postgres`): implement
  `UseStore` so each method matches `store::logic`, durably, each in one
  serializable transaction (the trait docs say what that means for
  `commit`). `bnap-store-tests` should call
  `bnap_core::test_support::conformance::run(make_store, &executor)` with
  an `Executor` for the store's runtime (deferred item S5c), and may add
  the state-machine scenarios of `src/outcome/tests.rs` through `process`.
  Persist the new record fields `keep_until`, `refund_cap` and `unit`;
  `settle(&SettleRequest)` must time a settle later than `created +
  req.pending_timeout()` out in the same transaction; `purge(&SweepWindow)`
  must keep a record until `keep_until + 60 < window.now()`. The request
  types have getters only: a store reads them and never builds one.
  `reserve_change(&ChangeRequest)` is the outcome's change ledger: lock
  the record's row (or run serializable), skip outputs already in it,
  add the rest only if the total stays within the smallest of the
  request's cap, `refund_cap` and the first OK cap, all in one
  transaction, and persist `change_total`, `change_cap_ok` and every
  output (keyset, amount, `B'`); settle, timeout and refund must never
  overwrite those columns from an older read. Run every conformance
  scenario, the concurrent ones included, on the store's own runtime.
- **Registry**: `policy::PROPERTIES` is an embedded copy of
  `registry/properties.toml`; replace it with the export and add a test
  that the order matches. The gate supplies each entry's vector and its
  binding class; `metered_entry_allowed(refund, upto)` must be called when
  building metered offers, since core has no registry access.
- **Gate** (`caparra-gate`): owns the offer-building loop (Pricer, then
  `scheme.offer`, `OfferID`, `scheme.native`, `UnsignedOffer`), the flow
  above, the per-address and per-offer bounds on plug work (section 12),
  stopping actions at `pending_timeout`, and the sweep schedule. It never
  prices or commits by itself: it calls `outcome::process` once per
  verified request and acts on the answer.
- **Native credentials** (5.4): `CredentialScheme::recover_native` exists
  with an unsupported default; the native envelope from part A
  (`credential::native_context`, `native_digest`) is not wired into a flow.
- **Signers** (`bnap-signer-file`, `bnap-signer-process`): `schnorr` MUST
  check that the key named by the `CoreMessage` is held for
  `purpose().key_use()`. `verify_unblinded` MUST compute `Y =
  hash_to_curve(secret)` itself (`bnap_core::note::hash_to_curve`), check
  `C = k·Y` against that point only, return it, and answer `None` for a
  keyset not in the given unit. `blind_sign` MUST refuse a keyset not in
  `limit.unit`, MUST refuse an empty batch and any output of amount 0, and
  MUST keep one running total per `ReplayKey`, across OK and FAILED, and
  keep it at least until `limit.keep_until` plus a clock skew:
  `ChangeLedger::reserve` before signing does the total and the dedupe,
  and `forget_expired(now)` drops only what may go. That total is a
  second line, not the bound: in memory, a restart or a second signer
  instance starts it from 0, and a scheme keeps whatever it got signed
  itself, so "the gate never sends change early" protects nothing. The
  bound across restarts and instances is the store's reservation
  (`UseStore::reserve_change`), which the gate's `CappedSigner` makes
  before every signer call (N3b-29). A signer may also persist and share
  its own total.
- **Gate**: give `CappedSigner::for_change` the same use store that
  committed the outcome (two gate instances share it); never call the
  signer's `blind_sign` except through a `CappedSigner`. Bound the number
  of change outputs a scheme may reserve per outcome (section 12, plug
  work): the store's ledger bounds their value at the admitted value but
  not their count, so a scheme could grow a record with up to `value`
  outputs of 1.
- **Gate**: pass each pay scheme's registered `refund` in `PayValue`
  (from the registry, never the plug); a missing or unknown value is
  `none`, which gives the scheme no change budget. Load limits with
  `Limits::from_manifest` (now a `Result`) and call
  `check_offer_lifetime` with the longest offer lifetime at start-up.
  Decide N3b-22 (replays of expired offers) with the owner; `process`
  already answers a known credential whatever its offer's expiry and
  refuses a new one with STALE, so the first option needs only the gate to
  call `process` for an authentic but expired offer.
- **Schemes** (`bnap-scheme-*`): an atomic scheme MUST make its FAILED
  refund a superset of its OK change (re-sign the change outputs, then add
  the refund outputs), as `bnap:notes` does: the signer bounds change and
  refund of one outcome together at the value, so a refund that signs
  fresh outputs for the whole value after a late OK settle is refused.
  `Verified.value` is a claim in the chosen
  pay entry's unit, and admission counts it only up to the backing. A
  facilitator or notes scheme must not rely on scheme-scoped `UseId`s for
  value the operator's signer confirmed: the socket consumes such a note
  under `H_"bnap/note"(Y)`, shared by every value scheme on the gate, so a
  Cashu adapter and `bnap:notes` can never both spend one note. Only a
  scheme registered `refund = "atomic"` gets a change cap above 0. A
  rail scheme names its payments in `rail_ids`; a notes scheme checks
  every note through `cx.signer.verify_unblinded(keyset, amount, secret,
  c)` and uses the `Y` it returns (the view keeps the note under that
  33-byte `Y`; the commit consumes it under `H_"bnap/note"(Y)` whatever the
  scheme's own use IDs are); a facilitator scheme (x402, card) needs a `FundingRail` of its
  kind to confirm its payments, or it is always UNDERPAID above price 0.
- **Stores** also need the `refund_recorded` flag and the
  `record_refund(rk, Option<&[u8]>)` rule of `store::logic`.
- Unit conversion is exact only between `sat` and `msat`; any other pair
  is refused. A gate that wants other conversions does them in the Pricer,
  when the offer is built.
- No WIT interface yet (the overview's v0.7 WASM plugs).
- Part A's review item on duplicate JSON member names in the manifest is
  closed (S1). A carrier that hashes JSON through JCS (MCP) should read it
  with `manifest::parse_strict` too.
- Owner decisions open from this node: N3b-1, N3b-15, N3b-16 (confirm
  that schemes MUST make the refund a superset of the change), N3b-22,
  N3b-23 (spec wording for replay detection before pricing), N3b-28
  (the overview's `verify_unblinded` signature) and N3b-29 (the change
  ledger belongs to the use store, not the signer alone).
