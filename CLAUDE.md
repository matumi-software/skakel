# Skakel

The transport between apps on a local network: discovery, pairing, tokens, a control hub and data
streams. Read `docs/protocol.md` first. Koppel (`matumi-software/koppel`) is the first app on it.

## Layout

The root stays clean: no code, no build files. Everything that builds lives under `src/`, one
folder per solution, each with its own `src/` and `tests/`.

| Folder | What |
|---|---|
| `docs/` | The protocol and decisions |
| `src/Skakel/` | The libraries: `Skakel.Client`, `Skakel.Server` and what they share (not created yet) |

## Rules

- **`docs/protocol.md` is the contract.** A change to what goes over the wire changes that file in
  the same pull request. Apps other than Koppel depend on it.
- **MIT, and nothing that would stop that.** Never copy GPL or LGPL code in, from Koppel's
  contributors included, and never take a dependency under those licences. Code from Koppel may
  move here only when its author agrees to MIT for it. Permissive code (MIT, BSD, Apache-2.0) may
  come in with its copyright and licence notice kept in the file.
- **No app logic.** Skakel moves bytes and state, and knows who is allowed to. A stream type that
  more than one app speaks (serial) has its wire format here, so apps of any licence can use it,
  but the code that opens a real port or device stays in the app. A type only one app uses (USB) is
  that app's.
- C#: file-scoped namespaces, internal by default, `[LoggerMessage]` for logging. Tests are named
  `Method_does_thing`.

## Git

Work from an issue, in a worktree `<repo>/<type>/RVR/<name>` branched from `origin/main`. Open a
pull request into `main` that says `Closes #N` and rebase-merge it. Releases are annotated `v*`
tags on `main`.
