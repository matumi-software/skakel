# Skakel

The transport between apps on a local network: discovery, pairing, tokens, a control hub and data
streams, plus the shared platform pieces those apps need, such as a Windows virtual camera. Read
`docs/protocol.md` first. Koppel (`matumi-software/koppel`, .NET) and Tweeling (Rust) use it.

Everything Skakel does exists in two languages, .NET and Rust, with the same feature set and the
same wire format. Each side is split into small parts so an app takes only what it needs.

## Layout

The root stays clean: no code, no build files. Everything that builds lives under `src/`, one
folder per solution or workspace.

| Folder | What |
|---|---|
| `docs/` | The protocol (`protocol.md`), the parts and what each depends on (`parts.md`), the virtual camera's contract (`virtual-camera.md`) and decisions |
| `src/Skakel/` | The .NET libraries: `Skakel.Protocol`, `Skakel.Discovery`, `Skakel.Pairing`, `Skakel.Serial`, `Skakel.Client`, `Skakel.Server` and `Skakel.VirtualCamera`, cut as `docs/parts.md` says, each with its tests under `src/` and `tests/`, and samples under `samples/`. The client's tests run against a real `Skakel.Server` on Kestrel. `Skakel.Discovery.Interop` is a small program the Rust discovery tests run to check both languages find each other |
| `src/rust/` | The Rust workspace, one crate per part (`skakel-<part>`), tests beside the code: `skakel-protocol`, `skakel-discovery`, `skakel-pairing`, `skakel-serial`, `skakel-client` (still empty), `skakel-server`, `skakel-vcam` (the camera's producer, ring and installer) and `skakel-vcam-source` (the camera's media source DLL) |

Build and test each side from its own folder:

```sh
cd src/Skakel && dotnet build && dotnet test
cd src/rust && cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## Rules

- **`docs/protocol.md` is the contract.** A change to what goes over the wire changes that file in
  the same pull request. Apps other than Koppel depend on it. Both languages follow it; a test that
  pins wire bytes in one has its counterpart in the other. `docs/virtual-camera.md` is the same for
  the camera's shared memory.
- **The virtual camera is never registered by a build or a test.** Installing the media source and
  creating a camera change the machine; that is a hand test, steps in `docs/virtual-camera.md`.
- **MIT, and nothing that would stop that.** Never copy GPL or LGPL code in, from Koppel's
  contributors included, and never take a dependency under those licences, or AGPL, in either
  language. Check a package's or crate's licence, and those it pulls in, before adding it. Code
  from Koppel may move here only when its author agrees to MIT for it. Permissive code (MIT, BSD,
  Apache-2.0) may come in with its copyright and licence notice kept in the file.
- **A part depends only on the parts it cannot work without.** `docs/parts.md` has the list and the
  allowed dependencies; a new project reference or package between parts changes that file in the
  same pull request. Both languages keep the same parts.
- **No app logic.** Skakel moves bytes and state, and knows who is allowed to. A stream type that
  more than one app speaks (serial) has its wire format here, so apps of any licence can use it,
  but the code that opens a real port or device stays in the app. A type only one app uses (USB) is
  that app's. The one exception is a platform piece more than one app needs and that carries no app
  behaviour of its own, such as the virtual camera: it lives here so it is written once.
- C#: file-scoped namespaces, internal by default, `[LoggerMessage]` for logging. Tests are named
  `Method_does_thing`.
- Rust: edition 2024, `cargo fmt` and `cargo clippy -D warnings` clean. Each crate's metadata comes
  from the workspace. Tests are named `does_thing` in a `tests` module or under `tests/`.

## Git

Work from an issue, in a worktree `<repo>/<type>/RVR/<name>` branched from `origin/main`. Open a
pull request into `main` that says `Closes #N` and rebase-merge it. Releases are annotated `v*`
tags on `main`.
