## What changed and why

## Issue

Closes #

## How it was tested

Run from `src/`:

```sh
cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

- [ ] Ran all four, and list here anything not run and why:

## Docs

- [ ] `docs/protocol.md` changed, for a change to the wire format (or none was needed)
- [ ] `docs/parts.md` changed, for a new dependency between crates (or none was needed)
- [ ] `CHANGELOG.md` has a line under Unreleased, for a change to the wire format or a crate's public API (or none was needed)

## Dependencies

- [ ] Any new dependency, and everything it pulls in, is MIT, Apache-2.0, BSD, ISC, Zlib, Unlicense or Unicode-3.0. Nothing is GPL, LGPL or AGPL. Licence checked with `cargo metadata` or `cargo info`.
