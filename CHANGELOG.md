# Changelog

## Unreleased

- `skakel-server`: every per-address limit counts an IPv6 address by its `/64`, so one host cannot
  spend a limit by rotating addresses. Pairing takes at most 64 requests that have not revealed for
  the whole server, and refuses a revealed nonce shorter than 43 characters with 404, as for any
  nonce that does not match. The address the app sees on a request is still the whole address.
- `skakel-server`: approving a pairing request no longer holds the pairing lock while the store
  saves the client, so a slow store does not stall other pairing calls, and a failed save leaves the
  request waiting for another try.
- `skakel-vcam`: `Section::region` is `unsafe`. The `Region` it returns is a `Copy` view with no
  lifetime, so safe code could write to memory after the section was unmapped. Apps that only use
  `VirtualCamera` are not affected.
- `skakel-vcam`: `Error::Camera`'s source is now the Windows error with its HRESULT (the message
  still carries the hint), where it was a formatted string.
- `skakel-vcam-source`: a panic inside the media source is logged and becomes `E_FAIL`, where it
  aborted the Frame Server process. A buffer that reports a negative or too short row pitch is
  refused instead of read out of range.
- Virtual camera layout contract: a producer that attaches after one died mid-write of the idle frame
  starts the idle version from the time, so readers no longer skip its first idle frame
  (`docs/virtual-camera.md`). Layout version 1 is unchanged.

## 0.2.1 (2026-11-12)

- `skakel-server`: `SkakelServer::start_discovery` and `stop_discovery` start and stop answering discovery
  probes while the server runs, so an app whose role changes at runtime answers only while it is a
  server. Stopping releases the UDP port before it returns, and both are safe to repeat. Nothing
  changes for an app that never calls them.

## 0.2.0 (2026-11-09)

Skakel is Rust only from this release, and speaks protocol version 2. Koppel 0.2.0 is built on it.
Breaking changes from 0.1.0:

- Protocol version 2 does not talk to version 1. A 0.2.0 client and a 0.1.0 server, or the other way
  round, cannot link: update both ends together. Each tells a person so through the version check.
  The spec is [docs/protocol.md](docs/protocol.md), with a table of what changed from version 1.
- SignalR and the WebSocket streams are gone. The control channel (`skakel.v2.ControlService`) and
  the data streams (`skakel.v2.StreamService`) are gRPC over HTTP/2, on the same pinned TLS
  certificate. Info, pairing and tokens stay plain HTTPS, now under `/skakel/v2/`, and discovery is
  unchanged apart from advertising `"versions": [2]`.
- Refusals and stream ends are gRPC status codes with a `google.rpc.ErrorInfo` reason, in place of
  HTTP statuses and WebSocket close codes.
- A token travels in the `authorization` metadata of each call only. The `access_token` query
  parameter is gone.
- The .NET packages (`Skakel.Protocol`, `Skakel.Server`, `Skakel.Client`) are no longer developed.
  Their source stays at tag `v0.1.0`.

What is in 0.2.0:

- The wire format is the `.proto` files in `src/proto/skakel/v2/`, so an app in any language can
  generate a client or server.
- Skakel is cut into small crates, so an app takes only what it needs (see
  [docs/parts.md](docs/parts.md)): `skakel-protocol`, `skakel-proto`, `skakel-discovery`,
  `skakel-pairing`, `skakel-serial`, `skakel-client` and `skakel-server`. They are not on crates.io;
  use them from the tag.
- `skakel-proto` generates the Rust code from the `.proto` files at build time, with `protox`, so no
  `protoc` is needed.
- The control channel is one long-lived connection, and each data stream gets a connection of its
  own.
- Apps add their own gRPC services beside Skakel's, on the same port. Skakel checks the token and
  ends the app's calls on revoke, rotate or stop.
- An app can serve Skakel on its own listener: `start_mounted`, `service()` and `tls_config()` mount
  Skakel on the app's server, with every per-address limit counted by the real caller and the
  certificate handover intact. `start()` still lets Skakel own the port.
- A client whose credentials are refused stops and says it has to pair again.
- The Windows virtual camera, in `skakel-vcam` (the producer, the frame ring and the installer) and
  `skakel-vcam-source` (the media source DLL). Its contract is
  [docs/virtual-camera.md](docs/virtual-camera.md).
- The Skakel mark is redrawn in the Matumi family stroke, and the social preview uses it.

## 0.1.0 (2026-11-05)

The first release of Skakel, the transport between apps on a local network. Koppel 0.1.1 is the first
app built on it.

- Protocol version 1, written up in [docs/protocol.md](docs/protocol.md) as it stood at this tag:
  UDP discovery, pairing with a six-digit code, OAuth 2.0 client credentials over a pinned
  self-signed certificate with a handover when it changes, a SignalR control hub, and WebSocket
  streams, including a standard serial stream type.
- `Skakel.Protocol`, `Skakel.Server` and `Skakel.Client`, .NET 10 libraries on NuGet.org: what
  clients and servers share; serving Skakel clients from ASP.NET Core; and finding servers, pairing,
  keeping a link per server and opening streams.
- Hardening from a security, dependency and packaging review: the server limits and caps requests
  before reading them, keeps answering discovery and tightens pairing; the client caps what servers
  send, clamps server-chosen timings and holds its ground against spoofed discovery answers. The
  packages are reproducible, and `Skakel.Server` depends only on OpenIddict's server and validation
  parts.
- The Skakel brand: mark, app icon and social preview.
