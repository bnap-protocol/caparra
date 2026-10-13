# Integration notes: N3 part A, `bnap-core` encoding and cryptography

Branch `node/n3a`, crate `crates/bnap-core` only. Normative source:
`bnap/spec/socket-draft-00.md` (doc rev 39), with `spec/ERRATA.md` and
`spec/DECISIONS.md`. Vectors: `bnap/vectors/vectors.json` at bnap commit
`14bbd5e`, copied to `crates/bnap-core/tests/data/vectors.json`.

## Public API

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

### How a gate uses it (4.4 order)

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

## Decisions made

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

## ERRATA list (ambiguities found, literal draft-00 reading taken)

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

## Tests

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

## Known gaps (for downstream nodes)

- No pricing (section 7), use store commit, settle or replay logic (6.3,
  6.4): `bnap-core` provides the IDs and keys those need.
- No base64url: carriers encode and decode headers themselves.
- The HTTP carrier still has to combine repeated fields (RFC 9110 5.3), cap
  credentials at `HTTP_MAX_CREDENTIAL`, compare `BNAP-Context`, and reject
  a request with more than one value credential (5.4).
- Client spend policy (4.4) is not modelled.
- Route `require` is carried as raw JSON values; its semantics belong to
  the judge.
- GREASE values need caller randomness (`tlv::grease_type(seed)` maps a seed
  to a GREASE type).
