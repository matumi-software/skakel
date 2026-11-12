# Skakel

The transport between apps on a local network: discovery, pairing, tokens, a control channel and
data streams over gRPC, plus the shared platform pieces those apps need, such as a Windows virtual camera. Read
`docs/protocol.md` first. Koppel (`matumi-software/koppel`) and Tweeling use it.

Skakel is Rust only from 0.2.0. It is split into small parts, one crate each, so an app takes only
what it needs. The .NET packages of 0.1.0 are no longer developed; their source is at the tag
`v0.1.0`.

## Layout

The root stays clean: no code, no build files. Everything that builds lives under `src/`, which is
the Cargo workspace.

| Folder | What |
|---|---|
| `docs/` | The protocol (`protocol.md`), the parts and what each depends on (`parts.md`), the virtual camera's contract (`virtual-camera.md`) and decisions |
| `src/` | The Cargo workspace, one crate per part (`skakel-<part>`), tests beside the code: `skakel-protocol`, `skakel-proto` (the code generated from `src/proto`), `skakel-discovery`, `skakel-pairing`, `skakel-serial`, `skakel-client`, `skakel-server`, `skakel-vcam` (the camera's producer, ring and installer) and `skakel-vcam-source` (the camera's media source DLL) |
| `src/proto/` | The `.proto` files of protocol version 2, the wire format of the control channel, the streams and the serial stream type. `skakel-proto` generates the Rust code from them at build time |

Build and test from `src/`:

```sh
cd src && cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## Rules

- **`docs/protocol.md` is the contract.** A change to what goes over the wire changes that file in
  the same pull request. Apps other than Koppel depend on it. Tests pin the wire bytes, and a change
  to a pinned value is a protocol change. `docs/virtual-camera.md` is the same for the camera's
  shared memory.
- **`CHANGELOG.md` records what an app can notice.** A change to the wire format or to a crate's
  public API adds a line to Unreleased in the same pull request.
- **The virtual camera is never registered by a build or a test.** Installing the media source and
  creating a camera change the machine; that is a hand test, steps in `docs/virtual-camera.md`.
- **MIT, and nothing that would stop that.** Never copy GPL or LGPL code in, from Koppel's
  contributors included, and never take a dependency under those licences, or AGPL. Check a
  crate's licence, and those it pulls in, before adding it. Code from Koppel may move here only
  when its author agrees to MIT for it. Permissive code (MIT, BSD, Apache-2.0) may come in with its
  copyright and licence notice kept in the file.
- **A part depends only on the parts it cannot work without.** `docs/parts.md` has the list and the
  allowed dependencies; a new dependency between crates changes that file in the same pull request.
- **No app logic.** Skakel moves bytes and state, and knows who is allowed to. A stream type that
  more than one app speaks (serial) has its wire format here, so apps of any licence can use it,
  but the code that opens a real port or device stays in the app. A type only one app uses (USB) is
  that app's. The one exception is a platform piece more than one app needs and that carries no app
  behaviour of its own, such as the virtual camera: it lives here so it is written once.
- Rust: edition 2024, `cargo fmt` and `cargo clippy -D warnings` clean. Each crate's metadata comes
  from the workspace. Tests are named `does_thing` in a `tests` module or under `tests/`.

## Git

Work from an issue, in a worktree `<repo>/<type>/RVR/<name>` branched from `origin/main`. Open a
pull request into `main` that says `Closes #N` and rebase-merge it. Releases are annotated `v*`
tags on `main`.

A pull request fills in `.github/pull_request_template.md`. `.github/CODEOWNERS` names the maintainers,
who review every change. Issues come from the forms in `.github/ISSUE_TEMPLATE/`, which set the
`type: ...` and `state: needs-triage` labels; add a `scope: ...` label when triaging.
