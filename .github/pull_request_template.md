## What this changes

<!-- One or two sentences. Link the issue it closes, if any. -->

## Spec reference

<!-- The socket-draft-00 section, scheme draft, DECISIONS or ERRATA row this
implements or follows, or "none". -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin).
- [ ] Tests added or updated; a fix comes with a test that fails without it.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo nextest run --workspace --locked` pass locally.
- [ ] `Cargo.lock` is committed if dependencies changed.
- [ ] Docs updated (README, `book/`, `CHANGELOG.md`) where behavior changed.
- [ ] `ops/leak-guard.sh` is clean.
