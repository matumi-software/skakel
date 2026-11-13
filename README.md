# Skakel

Skakel is the transport between apps on a local network. It covers how a client finds a server,
pairs with it, signs in, follows its state and moves data to and from it. Apps put their own
features on top.

[Koppel](https://github.com/matumi-software/koppel), which shares USB devices and serial ports over
the network, is the first app built on it.

*Skakel* is Afrikaans for a link in a chain, and to connect.

## Status

Version 0.3.0, Rust only. Protocol version 3 is specified in
[docs/protocol.md](https://github.com/matumi-software/skakel/blob/main/docs/protocol.md), with its
wire format in `.proto` files under `src/proto/skakel/` (`v3` for the control and stream services, `streams/serial/v1` for the serial stream type). The server and the client speak it:
gRPC for the control channel, the app's own calls and the data streams, beside HTTPS for info,
pairing and tokens, all on one TLS port pinned to the server's certificate. They are tested against
each other. Version 1 (a SignalR hub and WebSocket streams) is at the tag `v0.1.0`.

Up to 0.1.0 Skakel was a set of .NET packages. They stay on NuGet.org but are no longer developed,
and their source is at the tag `v0.1.0`.

## What it holds

One crate per part, in the Cargo workspace in `src/`:

| Crate | What |
|---|---|
| `skakel-wire` | What is on the wire apart from the generated messages: constants and paths, the JSON contracts, certificate fingerprints, the reasons a gRPC call is refused or ended, the discovery packet (`discovery`) and the pairing code and bodies (`pairing`) |
| `skakel-proto` | The Rust code generated from the `.proto` files of protocol version 3: the messages, and with the `client` and `server` features the tonic clients and servers |
| `skakel-serial` | The serial stream's target, line settings, modem lines and control messages, encoded as `serial.proto` says |
| `skakel-server` | Serve clients, protocol version 3: discovery answers, pairing approval, OAuth tokens, revoking clients, the control and stream services over gRPC, the app's own gRPC services behind Skakel's token check, the per-address limits and the self-signed certificate with its handover, all on one TLS port. tokio, hyper, axum, tonic and rustls; the app supplies a store, its gRPC services, stream types and the pairing screen |
| `skakel-client` | Find servers, pair, get tokens, pin the server's certificate, keep the control channel up (renewing it before its token runs out, following a certificate handover and a server that moved), call the app's own gRPC services over it, and open data streams, each on a connection of its own; on tokio, with tonic's generated clients over pinned HTTP/2 connections |
| `skakel-vcam` | Feed the virtual camera, and `skakel-vcam-install` to install its media source |
| `skakel-vcam-source` | The virtual camera's media source: the COM DLL Windows' Frame Server loads |

[docs/parts.md](https://github.com/matumi-software/skakel/blob/main/docs/parts.md) says what each
part holds and which one an app takes.

The crates are not on crates.io. An app takes them from this repository, pinned to a commit:

```toml
skakel-client = { git = "https://github.com/matumi-software/skakel", rev = "<commit>" }
```

## Rust version

Skakel needs Rust 1.99 (`rust-version` in `src/Cargo.toml`), the stable release when 0.3.0 was cut,
and edition 2024. CI builds and tests on the latest stable, which is the declared version, so there is no
separate job for an older toolchain. When stable moves past the declared version and the code does not
need the newer one, CI gains a job on the declared version, so the claim stays true.

## Virtual camera

A camera that Teams, Zoom, browsers and the Camera app list by name, fed with frames by an app, on
Windows 11 (`MFCreateVirtualCamera`, no driver). The media source is installed once per machine,
elevated; after that an app creates its camera and feeds it without elevation:

```rust
let mut camera = VirtualCamera::create(CameraOptions::new("Tweeling", 1280, 720, 30))?;
camera.set_idle_frame(&closed_picture, PixelFormat::Bgra)?;
camera.push_frame(&frame, PixelFormat::Bgra)?;
```

[docs/virtual-camera.md](https://github.com/matumi-software/skakel/blob/main/docs/virtual-camera.md)
has how it works, the shared memory contract, installing and upgrading, and signing.

## How it talks

- **Finding a server:** a UDP probe on the local network. A server answers with its name, port,
  certificate fingerprint and version.
- **Pairing:** an eight-digit code that a person compares on both machines, so no secret is ever
  typed or copied.
- **Signing in:** OAuth 2.0 client credentials. The client pins the server's certificate.
- **Control:** gRPC over HTTP/2 on the same port. Skakel's control service carries the certificate
  handover and closing; an app adds gRPC services of its own beside it for its commands and the
  state it pushes, signed in with the same token.
- **Data:** a gRPC stream for each USB device, serial port or app's own stream type, each on a
  connection of its own, with data and control messages in order.

## License

MIT, see [LICENSE](https://github.com/matumi-software/skakel/blob/main/LICENSE). Copyright (c) 2026 Matumi (Pty) Ltd.

Contributions are accepted under the same licence. Skakel takes no GPL code, so apps of any licence
can use it.
