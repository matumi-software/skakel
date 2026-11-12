# Changelog

## Unreleased

- `skakel-server`: public API clean-up, breaking for apps that match or construct these types.
  `#[non_exhaustive]` is now on `ServerEvent`, `ServerError`, `StreamOpen` and `Approval` (a `match`
  needs a wildcard arm) and on the structs `PairingRequest`, `PairingOverview`, `PairingDecision`,
  `ClientView`, `KeysView`, `CertificateSwitch`, `NewClient`, `StreamRequest`, `Principal`,
  `SkakelState`, `ClientRecord`, `CertificateRecord` and `NextCertificateRecord` (fields can still be
  read, and a store still saves and loads them through serde). `StreamOpen::Accept` now holds an
  `Accepted`, which only `StreamOpen::accept` makes. `CryptoError`, which `ServerError::Crypto`
  carries, can now be named. `clean_client_name` moved to `skakel-pairing`, which an app can use to
  clean a name the same way. `InMemoryStore::state` and `SkakelServerBuilder::token_lifetime` are
  test helpers and are there only with the new `test-util` feature. The crate forbids unsafe code and
  warns on undocumented public items.
- `skakel-client`: breaking changes to the public API, together, so apps move once:
  - reqwest is gone. Plain HTTPS runs over hyper's HTTP/1.1 client on the same pinned connector as
    gRPC. `Link::request` takes a `RequestBuilder` (`header`, `body`, `json`, `timeout`) and returns
    a `Response` (`status`, `headers`, `bytes`, `text`, `json`) of the client's own, read whole up to
    16 MiB. `Method` and `StatusCode` are the `http` crate's, `Url` the `url` crate's.
  - `pub use tonic` is gone: an app that builds tonic clients on `Link::channel` names `tonic` 0.14
    itself. `StreamClose::code` and `StreamRefusal::code` are the new `GrpcCode`, not tonic's `Code`.
  - Callbacks are gone: `on_status_changed`, `on_pins_changed` and `on_address_changed` are replaced
    by `Link::events` (a `LinkEvent` for each change, in order), `watch_status`, `watch_address` and
    `watch_pins` (the latest value), and `Link::set_pin_store` with a `PinStore`, which the link
    waits for before it tells the server it has the next certificate. A store that panics counts as
    not saved and cannot take the link down. `Browser::watch` and `SerialConnection::events` return
    the client's own `StateWatch` and `Events` instead of tokio's receivers; `SerialConnection` also
    has `watch_line_settings` and `watch_modem_status`, and `recv` gives `Bytes`.
  - `StreamConnection::into_io` gives a `StreamIo`, a stream's data as tokio's `AsyncRead` and
    `AsyncWrite`.
  - `Clock` has a new method, `instant`, a monotonic time; token expiry, pacing and the pairing wait
    use it, so a change of the system's clock no longer moves them.
  - `ClientOptions` and `BrowserOptions` are `#[non_exhaustive]` with builder methods; the enums and
    result structs an app matches on (`FailureKind`, `LinkState`, `LinkStatus`, `Frame`,
    `StreamCloseReason`, `StreamClose`, `StreamRefusalReason`, `StreamRefusal`, `PairingError`,
    `SerialEvent`, `SerialChange`) are `#[non_exhaustive]`, so an app needs a wildcard arm.
  - Internals are no longer public: `Error::new`, `Error::with_source`, `Error::of`, `Failure::of`,
    `Failure::version_mismatch`, and the `from_status` and constructor functions of `StreamClose` and
    `StreamRefusal`. `Browser::add_for_test` and `Link::following` are behind the `test-util`
    feature. `HandlerError` is `StoreError`.
  - `Token` no longer prints its value in `Debug`. `#![warn(missing_docs)]`, and the crate docs have
    a compiled example.
- `skakel-server`: access tokens are random strings the server remembers, not signed JWTs. Clients
  never read a token, so nothing changes for them, but a server that restarts forgets its tokens
  and clients ask for new ones (they already do on `TOKEN_REFUSED`). Breaking for apps: the signing
  key is gone, so `Keys::rotate_signing_key`, `KeysView::signing_key_id`,
  `KeysView::signing_key_since`, `KeysView::retired_keys_until`, `store::KeyRecord`,
  `SkakelState::signing_key`, `SkakelState::retired_signing_keys` and `ISSUER` are removed, and
  `ServerEvent::Keys` now means the certificate changed. A state file that still holds key records
  loads, and the next save drops them. `Principal` moves to a module of its own and keeps its
  name and fields.
- `skakel-server`: `Debug` of `NewClient`, `ClientRecord`, `KeyRecord` and `CertificateRecord` no
  longer prints client secrets or private keys. `FileStore` writes the state to a temporary file of
  its own, readable by the server's account only (mode 0600 on Unix), syncs it and renames it over
  the old one; a state file left with wider permissions is replaced by a private one on the next
  save. A client id another client already has is never reused, and a state that cannot be loaded
  is never saved.
- `skakel-server`: wrong secrets are counted per client and address, so someone who knows only a
  client id can no longer lock that client out of tokens from everywhere (`docs/protocol.md`,
  "Tokens"). HTTP Basic credentials are form-decoded whole: an id or secret with a literal `&` after
  it is refused instead of read up to the `&`.
- `skakel-server`: the limiters are swept at most every 5 seconds and hold at most 100,000 keys, so a
  flood from many addresses costs bounded time and memory. `shutdown` waits until the running calls
  have ended (at most 3 seconds) instead of a fixed 200 ms before it winds the connections down.
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
- `skakel-serial`: a value this end does not know (a new parity, stop bits, flow control or error
  code) is kept as `Unknown(value)` instead of dropping the message, so a newer server's message
  still arrives and a pending change is answered at once instead of timing out after 10 seconds.
  `ServerMessage::decode` returns a `Result` with the new `ServerMessageError`, as
  `ClientMessage::decode` does. `LineSettings::data_bits` is the new `DataBits` enum and
  `LineSettings::is_valid` says whether a port can be asked for the settings. The enums and both
  message enums are `#[non_exhaustive]`, so an app matching on them needs a wildcard arm.
  `skakel-client` re-exports `DataBits`. The wire is unchanged.
- `skakel-client`: a certificate handover the app's handler failed to save is offered to it again
  on the next connection and is acknowledged to the server only once the app has saved it (before,
  a reconnect acknowledged it unsaved, and the client had to pair again after a restart).
- `skakel-client`: `Link::request`, `Link::open_stream` and `Link::open_serial` return the new
  `FailureKind::InvalidRequest` for a path that leaves the server (control characters and spaces
  included), a stream type that is not one or an empty port id, where they panicked. Apps that
  match every `FailureKind` need an arm for it.
- `skakel-client`: `Link::start` starts a link that closed for good (credentials refused, revoked,
  rotated), where it did nothing until `stop()`. The info answer is refused when it lists more than 8
  versions, as discovery's is. A pairing wait goes on after a poll that failed on the network and
  gives up after 10 in a row; the poll uses the request timeout instead of 30 seconds. The pause
  between reconnect attempts is jittered and keeps growing for a connection that did not stay up
  for 30 seconds. Discovery datagrams outside the answer window are dropped before they are parsed.
  Access tokens are marked sensitive in headers, and one that cannot be a header value is refused
  when it is issued. `StreamConnection::closed` says it waits for unread frames.
Nothing yet. `main` is at the v0.2.1 tag.
- `skakel-pairing`: `PairPoll.state` is a `PairState` (`Waiting`, `Approved`, `Denied`, `Expired`, and
  `Unknown(String)` for a word added later) instead of a `String`; the JSON is the same words.
  `PairPoll::state` takes anything that converts into a `PairState`. `PairPoll` and `PairOpened`
  no longer print the client secret, the poll token or the server nonce through `Debug`.
- `skakel-discovery`: `net::probe`, `net::serve_one`, `net::Found` and `net::can_answer` are gone; no
  Skakel crate used them. `net::should_answer` stays. `AnswerError` is `#[non_exhaustive]`. `clean`
  no longer leaves a space at the end of a name it cut.
- `skakel-protocol`: `SkakelProblem` and `fingerprints::matches_der` are gone (use
  `matches_any_der`). `fingerprints::are_equal` no longer takes two strings with no hex digit, such
  as `":::"`, for equal. It compares without the constant-time step, since fingerprints are public.
- Pairing wording now says `/skakel/v2/` where it still said `/skakel/v1/`. The wire is unchanged.

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
