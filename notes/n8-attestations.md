# Integration notes: N8, attestation schemes

Branch `node/n8`, crates `crates/bnap-scheme-dpop` and
`crates/bnap-scheme-webbotauth`. Built on the `bnap-core` and `bnap-plug`
APIs of N3 (`notes/n3-core.md`); **neither crate was changed**. Normative
source: `bnap/spec/socket-draft-00.md`, with the registry entries
`httpauth:DPoP`, `httpauth:Bearer` and `httpsig:web-bot-auth`
(`registry/schemes.toml`). External specs: RFC 9449 (DPoP), RFC 7515, 7517,
7518, 7638, 8037 (JOSE), RFC 6750 (Bearer), RFC 9421 (HTTP Message
Signatures), RFC 9651 (structured fields) and
draft-ietf-webbotauth-httpsig-protocol-00 (Web Bot Auth, September 2026).

## What the two crates do

| Scheme | Crate, plug | Class (registry) | Use model (registry) | Local ID = quota ID |
| --- | --- | --- | --- | --- |
| `httpauth:DPoP` | `bnap_scheme_dpop::DpopScheme` | A | reusable | JWK SHA-256 thumbprint (RFC 7638) of the DPoP key, raw 32 bytes |
| `httpauth:Bearer` | `bnap_scheme_dpop::BearerScheme` | none | reusable | SHA-256 of the token; no quota ID |
| `httpsig:web-bot-auth` | `bnap_scheme_webbotauth::WebBotAuthScheme` | A | reusable | JWK SHA-256 thumbprint of the signing key, raw 32 bytes |

All three are attestations: `verify` returns `Verified { use_ids: [local],
rail_ids: [], value: 0, quota_id }`, `offer` gives no `params` and refuses
a pay role (`SchemeError::Unsupported`), `settle` is the default (none).
Effects (required, waive, discount, quota) come from the offer and are
applied by bnap-core's pricing; the plugs never see them.

No crate links OpenSSL. `cargo tree --workspace --all-features --target all
-i openssl-sys` matches nothing; the tree still holds one `secp256k1`
(0.29.1). DPoP verifies ES256 with `p256` 0.14 and `EdDSA` with
`ed25519-dalek` 2.2 (`verify_strict`); Web Bot Auth verifies Ed25519 with
Cloudflare's `web-bot-auth` 0.7.0. `josekit` was not used.

## Public API

### `bnap-scheme-dpop`

| Item | What it is |
| --- | --- |
| `DPOP`, `BEARER` | The scheme IDs |
| `DpopScheme::new(Arc<dyn Authority>)`, `.with_max_age(secs)` | The `httpauth:DPoP` plug |
| `BearerScheme::new(Arc<dyn Authority>)` | The `httpauth:Bearer` plug |
| `Authority` (async trait: `check_token(token, now) -> TokenStatus`, `check_key(&Thumbprint, now) -> bool`, default false) | The operator's word on access tokens (RFC 9068 validation or RFC 7662 introspection report `cnf.jkt`) and on DPoP keys registered without a token |
| `TokenStatus::{Active(TokenInfo), Inactive}`, `TokenInfo { jkt: Option<Thumbprint> }` (`bound_to`, `bearer`), `AuthorityError` | Authority answers; an error is UNAVAILABLE |
| `StaticAuthority` (`new`, `with_token`, `with_key`) | Fixed tokens and keys, for tests and small deployments |
| `Thumbprint` (`to_b64u`, `from_b64u`) | A JWK SHA-256 thumbprint |
| `BNAP_CTX_CLAIM` (`"bnap_ctx"`) | The JWT claim that carries the Context |
| `body::{DpopBody, BearerBody, dpop_types, bearer_types, MAX_PROOF, MAX_TOKEN, BodyError}` | The attest bodies |
| `proof::{check, ProofCheck, CheckedProof, ProofError, DPOP_TYP, MAX_JTI}` | The proof checks on their own |
| `jose::{parse_compact, Jws, PublicJwk, Alg, b64u, b64u_decode, JoseError}` | Strict compact JWS, JWK and thumbprints |
| `client::{ProofKey, ProofClaims, sign_proof, sign_raw, header, claims, body}` | The client side: proofs and bodies |
| `codes::*` | Scheme codes: `BAD_BODY`, `BAD_PROOF`, `UNSUPPORTED_ALG`, `BAD_KEY`, `BAD_SIGNATURE`, `WRONG_CONTEXT`, `STALE_PROOF`, `ATH_MISMATCH`, `INVALID_TOKEN`, `UNBOUND_TOKEN`, `KEY_MISMATCH`, `UNKNOWN_KEY`, `NOT_AN_ATTESTATION`, `DPOP_BOUND_TOKEN` |

### `bnap-scheme-webbotauth`

| Item | What it is |
| --- | --- |
| `ID`, `CONTEXT_FIELD` (`"bnap-context"`), `TAG` (`"web-bot-auth"`), `LABEL` (`"sig1"`), `DEFAULT_MAX_LIFETIME` (86,400) | Constants |
| `WebBotAuthScheme::new(authority, Arc<dyn KeyDirectory>)`, `.with_max_lifetime(Option<u64>)` | The plug; `authority` is the manifest origin's host (and port when not the default) |
| `KeyDirectory` (async trait: `resolve(&KeyQuery) -> Option<[u8; 32]>`), `KeyQuery { agent, keyid, now }`, `SignatureAgent { url, kind }`, `AgentType::{Directory, JwksUri, Cimd}`, `DirectoryError` | Key discovery, keyed on (agent URL, `keyid`); an error is UNAVAILABLE |
| `StaticDirectory` (`new`, `with_agent_key(url, key)`, `with_held_key(key)`) | Fixed keys, for tests and for pinned agents |
| `thumbprint(&[u8; 32])`, `keyid(&[u8; 32])`, `directory::thumbprint_input` | RFC 7638 / RFC 8037 thumbprints |
| `body::{WbaBody, types, MAX_FIELD, BodyError}` | The attest body |
| `client::{sign, SignParams, SignError}` | The agent side: a signature over the Context, as a body, always under `LABEL` (`SignParams` has no label field) |
| `codes::*` | `BAD_BODY`, `BAD_SIGNATURE_INPUT`, `UNSUPPORTED_COMPONENT`, `MISSING_COMPONENT`, `UNSUPPORTED_ALG`, `BAD_AGENT`, `BAD_KEYID`, `UNKNOWN_KEY`, `KEYID_MISMATCH`, `STALE_SIGNATURE`, `LIFETIME_TOO_LONG`, `BAD_SIGNATURE`, `NOT_AN_ATTESTATION` |

## Wire formats (proposed adapter specs)

No document defines these bodies yet (the notes vectors use a placeholder
Web Bot Auth body, `bnap-notes-draft-00` P37). What the crates implement:

**`httpauth:DPoP` body**, nested TLV: 0 `proof` (the DPoP proof JWT, compact,
the `DPoP` field value; required), 2 `access_token` (the token of
`Authorization: DPoP <token>`; optional). The proof is an RFC 9449 proof
whose claims also hold `bnap_ctx`: the credential's Context as 64 lowercase
hex digits. Required: header `typ` `dpop+jwt`, `alg` `ES256` or `EdDSA`
(`Ed25519` too), a public `jwk` (P-256 or Ed25519), no `crit`; claims `jti`
(at most 256 bytes), `htm`, `htu`, `iat` (integer), `bnap_ctx`; `ath` exactly
when a token is sent. ES256 signatures must have a low `s`.

**`httpauth:Bearer` body**, nested TLV: 0 `token` (RFC 6750 `b64token`).

**`httpsig:web-bot-auth` body**, nested TLV: 0 `signature`, 2
`signature_input`, 4 `signature_agent` (optional): the three field values,
each in its strict RFC 9651 serialization, one signature (one dictionary
member) each. The signature label is fixed: `Signature` and
`Signature-Input` both hold exactly one member, and its key MUST be `sig1`
(`LABEL`); any other label is BAD_BODY. RFC 9421 does not sign the label
(the signature base covers the components and `@signature-params`, not the
dictionary key), so a free label would let anyone rename it and get a
second body that verifies over the same Context. `sig1` is what the
`web-bot-auth` crate's own signer writes. The covered components are exactly `"@authority"`,
`"bnap-context"` and, when `Signature-Agent` is sent, the agent
(`"signature-agent";key="<member key>"` with a one-member dictionary, or the
legacy plain `"signature-agent"` with a String item). Parameters: `created`,
`expires`, `keyid` (base64url thumbprint), `tag="web-bot-auth"`; `alg`, if
present, `ed25519`; `nonce` optional. The gate supplies `@authority` from
its configuration and `bnap-context` as `b64u(Context)`, the `BNAP-Context`
field value of draft-00 10.2.

Every body is canonical (draft-00 5.1): unknown records (odd ones too),
empty records, oversize values and bytes outside the syntax are refused.

## How a gate wires them (for N9)

Per attestation part, after the 4.4 checks and before `outcome::process`:

1. Take the class and use model from the registry, never from the plug
   (DPoP: A, reusable; Bearer: none, reusable; Web Bot Auth: A, reusable).
2. `scheme.verify(part, &VerifyCtx { entry: Entry::Attest(e), context,
   digest, .. })`. The `signer` is unused; any verify-only `CappedSigner`
   will do.
3. On `Ok(v)`: push `VerifiedAttest::new(id, class)` with
   `.with_quota_id(q)` when `v.quota_use_id(id)` is `Some(q)`, and
   `SchemeUses { scheme: id, model: Reusable, local_ids: &v.use_ids }`.
4. On `Err(SchemeError::Rejected { .. })`: the attestation has no effect and
   causes no error (section 7); a required one becomes POLICY inside
   admission. Its body still goes in `attest_bodies` (it is in the Digest
   and the `ReplayKey`).
5. On `Err(SchemeError::Unavailable(_))` (authority or directory down):
   answer UNAVAILABLE, never admit (section 12, fail closed).

Configuration the gate owns: an `Authority` for DPoP and Bearer (token
validation or introspection, and any keys registered as API keys), a
`KeyDirectory` for Web Bot Auth (HTTPS fetch of the agent's directory,
caching, the SSRF rules of draft 6.7, and which agents the operator
honours), and the authority string for `WebBotAuthScheme::new` from the
manifest origin. The carrier compares `BNAP-Context` with the Context
(draft-00 10.2); the scheme never reads it. Bound the work of
unauthenticated requests per section 12: the plugs run cheap checks first
and call the authority or directory last, but the gate still owns
per-address and per-offer limits.

A trusted authority or directory is required, not optional. A DPoP proof
or an HTTP signature proves possession of a key; anyone can make a key. If
`Authority::check_key` accepted every key, or a directory resolved every
URL, a waive or discount would apply to everyone, and a quota counted per
key would be unlimited (a client mints keys).

## For the wallet (N10)

- Build the credential's parts first, with the attestation bodies empty:
  the Context covers the scheme IDs but no body, so it is final before any
  attestation is signed. Then sign, set the bodies, then sign class S
  witnesses over the Digest (which covers the attestation bodies).
- DPoP: `client::sign_proof(&ProofKey, &ProofClaims { context, htm, htu,
  iat, jti, access_token })`, then `client::body(&proof, token)`. Use a new
  `jti` per credential: two byte-identical requests with the same proof are
  one credential (a replay); with different `jti` they are two actions.
  `ProofKey` writes low-`s` ES256 signatures; a proof from another JOSE
  library must be normalized the same way or it is refused.
- Web Bot Auth: `client::sign(&SigningKey, &SignParams { authority,
  context, agent, created, expires, nonce })` returns the body, always under
  the label `sig1`; a wallet that copies a signature from its HTTP layer
  must use that label there too. Pick
  `expires` to cover the offer's expiry plus `pending_timeout` and a clock
  skew if the wallet may replay the credential to fetch a missed receipt
  (see ERRATA N8-3), and at most 24 hours after `created`.

## For e2e (N15)

- The flows in `tests/process.rs` of each crate are the reference gate
  wiring above, on `MemoryStore`, with a stub class S notes scheme (its
  witness is a BIP-340 signature over the Digest) standing in for
  `bnap:notes`.
- External vectors checked: RFC 8037 A.3 thumbprint; RFC 9449 figure 13
  (proof decodes, its key's thumbprint is the section 6.1 `jkt`, `ath`
  matches the token, the ES256 signature verifies in its low-`s` form);
  draft-ietf-webbotauth-httpsig-protocol-00 appendix E.2.1 and E.2.2 (both
  Ed25519 signatures verify over the signature base this crate builds, and
  are refused as BNAP attestations because they do not cover
  `bnap-context`); the test key's `keyid` `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`.

## Decisions made

- **Class A means the artifact embeds the Context**: DPoP through the
  `bnap_ctx` claim, Web Bot Auth through the covered `bnap-context`
  component. Neither covers the Digest, so neither has a witness; a witness
  on either part is refused.
- **Signature bases come from the gate only** (draft-00 5.1). `VerifyCtx`
  carries the Context but no carrier scope inputs, so DPoP does not compare
  `htm` and `htu` (the Context's action scope already binds method, target,
  content and listed headers) and Web Bot Auth takes `@authority` from its
  configuration and refuses every other request component.
- **The identity is the key's thumbprint**, as the registry says, computed
  by the scheme from the key itself: for Web Bot Auth the directory's key
  must hash to the `keyid` the signature names (`KEYID_MISMATCH`).
- **Canonical bodies** (draft-00 5.1): TLV records, base64url (no padding,
  zero trailing bits), I-JSON (`manifest::parse_strict` refuses a member
  named twice), exact `bnap_ctx` hex, low-`s` ES256, strict
  structured-field serializations with one signature and one agent member,
  one fixed Web Bot Auth label (`sig1`), and no small-order Ed25519 key
  (DPoP through `verify_strict`, Web Bot Auth through an `is_weak` check,
  since the `web-bot-auth` crate calls the non-strict `verify`; Ed25519 `S`
  is checked canonical, as the tree does not enable
  `legacy_compatibility`). The tests that prove it: a high-`s` twin of a
  valid DPoP proof is refused; a Web Bot Auth body renamed from `sig1` to
  any other label (both fields) still verifies over the crate but is
  refused, admits nothing and takes no quota slot; a signature forged under
  the identity-point key (R = B, s = 1) is refused. So nobody on the path
  can commit a re-encoded attestation-only credential under another
  `ReplayKey`.
  - Correction (repair round 1): an earlier hand-off claimed canonical
    bodies were "enforced in full" while the Web Bot Auth label was free.
    It was not: renaming `sig1=` in both fields gave a second verifying
    body, so an observer could rerun a waived action, drain a quota, or
    commit first (class O or none pay with a Web Bot Auth discount) and
    leave the client's credential SPENT. Fixed by the fixed label.
- **Without DPoP binding a token is class none.** `DpopScheme` refuses a
  token bound to no key (`UNBOUND_TOKEN`); `BearerScheme` refuses a token
  bound to a key (`DPOP_BOUND_TOKEN`, RFC 9449 7.1). bnap-core already
  refuses offers in which class none waives, discounts or carries a quota,
  and ignores such effects at pricing; the tests prove both through
  `process`.
- **No DPoP `max_age` by default**: the offer's expiry bounds a proof's
  age. `with_max_age` adds one for operators who want it. `iat` may be at
  most one clock skew (60 s) in the future.
- **Web Bot Auth time rules**: `created <= now + 60`, `now <= expires +
  60`, `expires >= created`, and `expires - created <= 86,400` by default
  (the draft's recommendation to agents).
- **Signature-Agent**: https only; a member of a type this verifier does not
  know, or a `directory` member that is not an origin, is ignored (draft
  5.2.1, 5.5) and the key must then be one the verifier holds; a request
  without `Signature-Agent` resolves only against held keys (draft 4.3).
- **ed25519-dalek stays on 2.2** (the line `web-bot-auth` uses), so the
  tree carries one copy; `p256` 0.14 shares `sha2` 0.11 with bnap-core.
  Duplicates that remain (`sha2` 0.10, `base64` 0.22, `signature` 2, `der`
  and `spki` 0.7, ...) all come from `web-bot-auth` and are cargo-deny
  warnings only.

## ERRATA candidates (literal draft-00 reading taken)

| # | Where | Ambiguity | What the crates do |
| --- | --- | --- | --- |
| N8-1 | registry `httpauth:DPoP` | "the claim name is for the adapter spec" | `bnap_ctx`, the Context as 64 lowercase hex digits; any other spelling is refused |
| N8-2 | draft-00 5.1, bnap-plug `VerifyCtx` | "build the signature base from the gate's own Context and the carrier's scope inputs", but schemes receive no scope inputs (method, target, authority) | DPoP checks `htm`/`htu` for presence only; Web Bot Auth takes `@authority` from configuration and accepts no other request component (no `@target-uri`, `@path`, `@method`). A later `VerifyCtx` could carry the scope inputs; not changed here |
| N8-3 | draft-00 6.1, 6.4 | A replay is verified again, and an attestation that no longer verifies (an expired Web Bot Auth signature, an expired or revoked token, a key removed from a directory, a DPoP `max_age`) drops its UseIds from the `ReplayKey`, so the replay no longer finds its outcome: attestation-only gives UNDERPAID or POLICY instead of the recorded response, and with notes the notes are SPENT. No double spend, but receipt fetching by replay and crash refunds can be lost | DPoP has no age limit by default; Web Bot Auth enforces `expires` as the draft says; wallets are told to sign long enough. Owner decision: should the gate key the replay lookup on the attestation's claimed local IDs, or verify replays at the commit's time? |
| N8-4 | draft-00 5.1 "Canonical bodies" | ECDSA signatures are malleable (`s` and `n - s` both verify), and RFC 7518 does not require low `s` | ES256 needs low `s`; standard JOSE clients must normalize. The adapter spec should say so |
| N8-5 | draft-ietf-webbotauth-httpsig-protocol-00 5.2.1 vs E.2.1 | The text requires the member "keyed to the signature label"; the draft's own vector covers `key="agent2"` under label `sig2` | Any one covered member is accepted; the dictionary must hold exactly that member |
| N8-6 | registry `httpsig:web-bot-auth`; draft-ietf 4.1 | The draft makes the Signature-Agent URL the identifier (it survives key rotation); the registry's `local_id` and `quota_id` are the key thumbprint | The thumbprint, as the registry and the task say: a quota restarts when an agent rotates its key. The registry `spec` also still points at draft-meunier-webbotauth-httpsig-protocol-00 |
| N8-7 | registry `httpsig:web-bot-auth` vs draft-ietf 4.3, 5.2.1 | Registry body: "if sent, Signature-Agent"; the draft: "A signed request MUST carry Signature-Agent", yet 4.3 covers verifying without a URL | Accepted without the field; only keys the verifier holds can then match |
| N8-8 | registry `httpauth:DPoP` | `local_id` is "the DPoP key's JWK thumbprint, the token's `cnf.jkt`"; nothing covers a DPoP key without a token ("API keys with DPoP") | The proof key's thumbprint in both cases; without a token the `Authority` must have registered the key |
| N8-9 | draft-00 section 7, registry `theft = bearer` | A class A attestation covers the Context, not the Digest, so anyone who sees a credential can put its attestation in another credential with the same Context and another pay body: the same discount, or a slot of the same quota, for the same request | Inherent to class A; documented. Quotas can be drained by an observer of the client's credentials |
| N8-10 | RFC 9449 4.3 step 10, draft-00 | BNAP has no `DPoP-Nonce` round trip | `nonce` is not checked; the OfferID in the Context is the server-chosen freshness |
| N8-11 | RFC 7515 4.1.9 | `typ` is a media type, compared case-insensitively | Only `dpop+jwt` exactly (a client's own signed value; strict costs nothing) |
| N8-12 | draft-00 5.1 "Canonical bodies"; RFC 9421 2.5, 4.2 | The signature label is not in the signature base, so any HTTP-signature attestation body that carries `Signature` and `Signature-Input` has as many encodings as there are labels | The label is fixed to `sig1` and any other is BAD_BODY. The adapter spec for `httpsig:web-bot-auth` (and any later `httpsig:` scheme) must fix it too |
| N8-13 | draft-00 5.1; RFC 8032 5.1.7 | RFC 8032 does not refuse small-order public keys, and under one anyone can make a verifying Ed25519 signature for any message | Small-order keys are refused: Web Bot Auth answers UNKNOWN_KEY (tested with a forged identity-point signature); DPoP checks `EdDSA` with `verify_strict`, which refuses them as BAD_SIGNATURE (library behaviour, no DPoP test of its own). The adapter spec should require it |

## Tests

- `bnap-scheme-dpop`: 26 (unit: JOSE vectors, base64url, keys, JWS,
  bodies; `tests/process.rs`: through `process`).
- `bnap-scheme-webbotauth`: 23 (unit: thumbprints, bodies, the draft's
  Ed25519 vectors, agent parsing; `tests/process.rs`: through `process`).

Through `process`, for each scheme: waive and discount apply for classes S,
A and O and not for none (the class overridden in the gate's registry);
DPoP bearer tokens can never waive or discount (offer builder refusal, and
pricing ignoring a misconfigured offer), and may satisfy `required`; a
proof or signature over another Context (another request, another offer,
the credential without its pay part, another extension, another authority)
is refused and the discount is gone; a stripped attestation changes the
Context and the Digest, and a swapped or altered one changes the Digest,
so the class S witness fails (BAD_CREDENTIAL); quotas count down (counter
read from the store), refuse past the limit (UNDERPAID without pay, full
price with pay), count per key, reopen in the next epoch, and a
quota-priced credential still replays from its record; an attestation-only
credential's replay returns the recorded outcome with `replayed`; the same
attestation under another `ReplayKey` runs twice (reusable) and is SPENT
under a single model; required attestations; time rules; malformed headers,
claims, components and parameters; authority and directory outages fail
closed. For Web Bot Auth also: a body relabelled from `sig1` (with an
agent, and with a held key and no agent) is refused, waives nothing, and
the client's own credential still replays its outcome; on a quota of 2 a
relabelled copy takes no slot and the agent's next fresh credential is
admitted; a signature forged under a small-order key is refused.

Mutation probes (run in this worktree, reverted): dropping the `bnap_ctx`
comparison, the low-`s` check, the `bnap-context` requirement or the
`keyid` check each turns tests red. Repair round 1: relaxing the fixed
label back to "the two labels match" turns four tests red (two unit, two
through `process`); the small-order key test failed (admitted) before the
`is_weak` check existed.

## Status at hand-off

- `cargo-q nextest run -p bnap-scheme-dpop -p bnap-scheme-webbotauth`: 45
  passed.
- `cargo-q clippy -p bnap-scheme-dpop -p bnap-scheme-webbotauth
  --all-targets --locked -- -D warnings`: clean (pedantic, `missing_docs`).
- `cargo-q fmt --all --check`: clean.
- `RUSTDOCFLAGS="-D warnings" cargo-q doc -p bnap-scheme-dpop -p
  bnap-scheme-webbotauth --no-deps`: clean; `cargo-q test --doc` for both:
  no doctests, green.
- `cargo-q +1.94 check -p bnap-scheme-dpop -p bnap-scheme-webbotauth
  --all-targets --locked`: clean (MSRV).
- `cargo-q deny --all-features check bans licenses sources`: ok;
  `advisories`: ok.
- `cargo-q tree --workspace --all-features --target all -i openssl-sys`:
  no match.

## Merge notes

- Root `Cargo.toml` gains three `[workspace.dependencies]`: `p256 = {
  version = "0.14.0", default-features = false, features = ["ecdsa", "std"]
  }`, `ed25519-dalek = "2.2.0"`, `sfv = "0.13.0"`. `web-bot-auth` 0.7.0 was
  already declared. `Cargo.lock` is committed; regenerate it on conflict.
- `josekit` is still declared in `[workspace.dependencies]` though no crate
  uses it; it links OpenSSL through `openssl-sys`, so any crate that opted
  in would break the no-OpenSSL rule. Suggest removing it.

## Known gaps

- No access-token validator (RFC 9068 JWT profile) or introspection client
  (RFC 7662): `Authority` is the extension point, `StaticAuthority` the
  only implementation.
- No HTTP key directory fetcher, no signed directory responses (draft
  appendix B): `KeyDirectory` is the extension point, `StaticDirectory` the
  only implementation. `StaticDirectory` compares agent URLs byte for byte;
  draft 5.5 compares identifiers after RFC 3986 syntax- and scheme-based
  normalization, which a real directory should apply (and it should resolve
  a `directory` member at the origin's well-known URI).
- Algorithms: DPoP ES256 and `EdDSA` only (no RS256, PS256, ES384); Web Bot
  Auth Ed25519 only (the `web-bot-auth` crate verifies nothing else).
- No signer or settle path: attestations carry no value.
- `bnap-scheme-notes` is not used; the tests' notes scheme is a stub.
