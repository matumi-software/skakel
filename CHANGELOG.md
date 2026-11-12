# Changelog

## Unreleased

- `skakel-server`, `skakel-client` and the wire: a server takes new pairing requests only while its
  app has opened a pairing window. Breaking for apps: pairing is **closed by default**, so an app
  calls `SkakelServer::open_pairing(duration)` (or `Pairing::open_pairing`; held to one minute up to
  one hour, calling it again moves the end) while a person is at the server, and `close_pairing()`
  to end it. `pairing_window()` says whether it is open and for how long, and a new
  `ServerEvent::PairingWindow` tells the app when it opens or closes (the window runs out by itself).
  An unattended server keeps today's behaviour with `SkakelServerBuilder::pairing_always_open()`.
  Outside the window `POST /skakel/v2/pair` gets 403 with the problem `reason` `pairing-closed`,
  reads no body and spends no pairing limit; requests already open carry on. The client reports it
  as the new `PairingError::Closed` and `FailureKind::PairingClosed` with the fixed wording "This
  server is not taking pairing requests. Open pairing on the server and try again." Apps with a test
  server that pairs build it with `pairing_always_open()`.
- Protocol version 3, pairing: the code a person compares is 8 digits, not 6, and is made from the
  client's name as well as the certificate and both nonces, so a man in the middle that shows the
  person another name than the client sent gets a code that does not match. Every hash input is
  length-prefixed (`skakel-pair-v2`, commitment `skakel-commit-v2`); the derivation is in
  `docs/protocol.md` ("Pairing"). Breaking for apps: `skakel_wire::pairing::compute` takes the client
  name (as sent) before the nonces, `DIGITS` is 8, `is_code` wants 8 digits, `commit` gives a
  different value for the same nonce, and an app that shows the code or asks the person for it shows
  and asks for 8 digits. A client of protocol 2 and a server of protocol 3 do not pair.
- Protocol version 3, discovery over IPv6: a client also sends its probe to `ff02::1` on each IPv6
  network it is on (from an address that is not link-local, so the answer comes from one too), and a
  server whose HTTPS listens on an IPv6 address (or whose `discovery_bind` is one) answers on an
  IPv6-only UDP socket of its own beside the IPv4 one, on the same port. A client ignores an answer
  from a link-local address (`fe80::/10`), which cannot be dialled without a zone. The browser's
  limit of 8 entries per address counts an IPv6 address as its `/64`. Apps that name the addresses
  to probe (`BrowserOptions::probe_targets`) may name IPv6 ones. The packets are unchanged. IPv4-only
  servers (`listen` on an IPv4 address) answer IPv4 only, as before. `skakel-server` and
  `skakel-client` now depend on `socket2` for the IPv6-only sockets.
- Protocol version 3, lengths: the limits on a name (63), an app version (32) and a client name (80)
  count Unicode scalar values, not UTF-16 code units (an emoji counts for one, not two), and the
  discovery answer is plain `serde_json` (non-ASCII text is UTF-8, not `\uXXXX` escapes). The answer
  still never exceeds the 512-byte probe: a name that does not fit is cut by scalar values.
- **Protocol version 3** (wire changes, together: a version 3 end does not talk to a version 2 end,
  and each tells a person so through the version check; `docs/protocol.md` has "Changes from version
  2"):
  - The version is 3: `/skakel/v3/...` paths, the gRPC package `skakel.v3` (the proto files moved to
    `src/proto/skakel/v3/`), `"versions": [3]` in discovery and info. `skakel_wire::VERSION`,
    `BASE_PATH`, `PAIR_PATH` and `TOKEN_PATH` follow; `skakel_proto::v2` is now `skakel_proto::v3`.
  - Fingerprints on the control channel are their 32 bytes: `Certificates::fingerprint`,
    `next_fingerprint` and `NextCertificateReceived::fingerprint` are `bytes`, empty for none.
    Discovery and info JSON keep the colon form. `skakel_wire::fingerprints` has `BYTES`,
    `bytes_of_der`, `to_bytes` and `from_bytes` for the conversions.
  - The serial messages have a package of their own, `skakel.streams.serial.v1`, in
    `src/proto/skakel/streams/serial/v1/serial.proto`, so the stream type versions apart from the
    core: `skakel_proto::serial` holds them. A line settings change carries a nonzero `request_id`
    and its answer (`line_settings` or `error`) carries it back. `skakel_serial::ClientMessage::LineSettings`
    and `ServerMessage::LineSettings` are struct variants with `request_id` and `settings`,
    `ServerMessage::Error` has a `request_id` (0 for an error the port reported on its own), and a
    change with a `request_id` of 0 decodes as the new `ClientMessageError::NoRequestId`.
    `SerialConnection::set_line_settings` takes the answer that carries its id and no other, so an
    answer that comes after its change gave up can no longer be taken for the next one.
  - TLS 1.3 only on both ends: a client that offers only TLS 1.2 gets a failed handshake.
  - A rule for evolution (removed fields are `reserved`, unknown oneof arms and enum values are
    ignored) is in `docs/protocol.md` and the proto files.
- `skakel-server`: the server no longer panics when the operating system has no random bytes. A
  request that needs them is refused and the error is logged: a pairing open is answered as for a
  full server, the token endpoint answers 500, and `register_client` and `rotate_secret` return the
  new `ServerError::Random`. `skakel-wire` has `pairing::random_bytes` and `RandomError::new`.
- `skakel-server`: any `SkakelStore` that still holds the signing keys of an earlier build is saved
  once without them when the server starts, not only `FileStore`; a failed save is logged and the
  next save drops them. `SkakelState` carries them as a read-only field for that, so a custom store
  that serialises the state with serde needs nothing.
- `skakel-proto` depends on `skakel-wire` and converts between its messages and `skakel-wire`'s
  types: `ClosingReason` and `Reason` (`From` both ways, and `closing_reason` for the number in a
  `Closing` message), `HelloResponse` and `SkakelHello`. `SkakelHello` stays: it is what an app
  gets from `Link::hello` and can pass on as JSON.
- `skakel-protocol`, `skakel-discovery` and `skakel-pairing` are now one crate, `skakel-wire`. They
  released in lockstep and were each a few hundred lines of plain data, so an app took two or three
  crates for one idea. An app changes its Cargo dependency and its `use` paths (the code is moved,
  not changed; history follows the files). `skakel-proto` may now depend on `skakel-wire`
  (`docs/parts.md`). Still no prost or tonic in `skakel-wire`.

  | Before | After |
  |---|---|
  | `skakel_protocol::X` | `skakel_wire::X` |
  | `skakel_protocol::fingerprints` | `skakel_wire::fingerprints` |
  | `skakel_discovery::X` | `skakel_wire::discovery::X` |
  | `skakel_pairing::X` | `skakel_wire::pairing::X` |

## 0.2.1 (2026-11-12)

This release replaces the first 0.2.1 build, which was withdrawn the same day: it carries the
fixes of an architecture and code review on top of it, and several of them break the public API of
the crates (listed below), so an app that took the first build moves once, here. The wire is
unchanged: protocol version 2 as 0.2.0 speaks it.

- `skakel-server`: a token or pairing request whose body stops arriving no longer holds its connection
  for as long as the client likes: the body has 10 seconds to arrive in full, and a request that
  misses that gets 400. A body over the message limit on `ControlService.Hello` now ends with
  `RESOURCE_EXHAUSTED`, as the protocol says, where tonic's `OUT_OF_RANGE` came through before.
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
- `skakel-client`: more API changes in the same move.
  - `Credentials` and the poll token of a `PairingClient` are overwritten with zeros when they are
    dropped (each clone's secret too; best effort, as copies the app made are not reached). Because
    of that, `Credentials` has a `Drop` and its fields cannot be moved out by value: clone them
    (`credentials.client_id.clone()`) or read them by reference.
  - `Browser::new` takes a `BrowserOptions` (`BrowserOptions::new(port)` with `app_ids`,
    `probe_targets` and `probe_interval`); `Browser::with_options` and the old
    `Browser::new(port, app_ids)` are gone.
  - `DiscoveredServer` is `#[non_exhaustive]`: an app does not build one. A test builds it with
    `DiscoveredServer::for_test`, behind the `test-util` feature.
  - `SerialConnection::into_io` gives a `SerialIo`, the port's data as tokio's `AsyncRead` and
    `AsyncWrite`; the line settings, modem lines and events stay on `SerialIo::connection`.
- `skakel-server`: more API clean-up, breaking for apps, in the same release as the rest.
  - Stream types: `StreamHandler` is now a trait with `async fn open(&self, StreamRequest) ->
    StreamOpen`, and every async function or closure of that shape implements it, so
    `.stream("echo", |request: StreamRequest| async move { ... })` works as it is. It was an
    `Arc<dyn Fn(..) -> BoxFuture<..>>` alias; `SkakelServerBuilder::stream` takes the handler itself
    and `BoxFuture` is no longer exported (return `impl StreamHandler` from a function, or write
    `async` blocks).
  - Events: one channel, `SkakelServer::subscribe`. `SkakelServerBuilder::on_event` and `on_pairing`
    are gone, and `subscribe` returns the server's own `ServerEvents` (`recv` and `try_recv`, an
    event missed by a slow reader is skipped), not tokio's receiver. To move over, call `subscribe`
    right after `start` and match `ServerEvent::Pairing` on a task of the app's own; the server no
    longer runs app code on its tasks.
  - `ServerError::State(String)`, `Invalid(String)` and `Options(Vec<String>)` are typed:
    `State(StateError)`, `Tls(source)`, `InvalidName`, `InvalidReason(String)` and
    `Options(Vec<OptionProblem>)`, each with its cause on `source()` and the same words in `Display`.
  - `Keys`, `KeysView` and `SkakelServer::keys` are `Certificates`, `CertificatesView` and
    `SkakelServer::certificates`, and `ServerEvent::Keys` is `ServerEvent::Certificates`, because
    they only cover the certificates now.
  - `FileStore` rewrites a state file that still holds the signing keys of an earlier build when it
    loads it, so the old private key does not stay on disk until the next change.
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
- `skakel-vcam`: the media source reads the DACL of a section that exists and uses it only when it
  is the one it would have made for that camera's producer, so a camera made with another user's id
  cannot show that user's frames. Local Service gets read and write on the section, not full access.
  A producer SID that names a group (Everyone, `BUILTIN\Users`, Interactive) counts as no SID.
  `docs/virtual-camera.md` has the rule, what it does not stop, and the hand tests.
- `skakel-vcam`: `install` loads and installs one copy of the DLL, made inside the install folder;
  `uninstall` leaves a registration that points elsewhere alone and reports it; `Installed` has a new
  field `left_behind`, and one old file that cannot be removed no longer stops the install.
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
- `skakel-server`: `SkakelServer::start_discovery` and `stop_discovery` start and stop answering discovery
  probes while the server runs, so an app whose role changes at runtime answers only while it is a
  server. Stopping releases the UDP port before it returns, and both are safe to repeat. Nothing
  changes for an app that never calls them.
- `skakel-pairing`: `new_nonce` returns a `Result` (`RandomError` when the operating system has no
  random numbers) instead of panicking. `compute` returns an `Option`: `None` unless the fingerprint
  is exactly 64 hex digits with optional colons, where it used to drop any other character and hash
  the rest; the code for a valid fingerprint is unchanged. `skakel-client`: `PairingError` has a new
  variant `NoRandomness`.
- `skakel-protocol`: `Reason` is `#[non_exhaustive]` (an app matching it needs a wildcard arm) and
  `Reason::ALL` is a slice. `Reason::code` and `STREAM_TYPE_CODE` are the new `GrpcCode`, which
  moved here from `skakel-client` (which re-exports it) and has `number` and `from_number`.
  `skakel-client` no longer has `From<tonic::Code> for GrpcCode` or the reverse.
- Protocol versions are `u32` in `SkakelInfo::versions`, discovery's `DiscoveryAnswer::versions`,
  `DiscoveredServer::versions`, `pick_version` and `require_version`, where they were `i32`. The JSON
  is the same; a negative version is refused when it is read, as a 0 always was.

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
