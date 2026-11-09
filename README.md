# Skakel

Skakel is the transport between apps on a local network. It covers how a client finds a server,
pairs with it, signs in, follows its state and moves data to and from it. Apps put their own
features on top.

[Koppel](https://github.com/matumi-software/koppel), which shares USB devices and serial ports over
the network, is the first app built on it.

*Skakel* is Afrikaans for a link in a chain, and to connect.

## Status

Version 0.2.0, Rust only. Protocol version 2 is specified in
[docs/protocol.md](https://github.com/matumi-software/skakel/blob/main/docs/protocol.md), with its
wire format in `.proto` files under `src/proto/skakel/v2/`. The client and server crates still speak
version 1, with a SignalR hub and WebSocket streams, and are tested against each other; they move to
version 2 next.

Up to 0.1.0 Skakel was a set of .NET packages. They stay on NuGet.org but are no longer developed,
and their source is at the tag `v0.1.0`.

## What it holds

One crate per part, in the Cargo workspace in `src/`:

| Crate | What |
|---|---|
| `skakel-protocol` | Wire constants and paths, the JSON contracts, certificate fingerprints, the hub's messages and the close codes |
| `skakel-discovery` | The discovery packet (probe, answer, cleaning, limits) and a small `std` UDP helper for answering and probing |
| `skakel-pairing` | The pairing code, nonces and commitments, and the JSON bodies of the pairing calls |
| `skakel-serial` | The serial stream's line settings, modem lines and control messages |
| `skakel-server` | Serve clients: discovery answers, pairing approval, OAuth tokens, revoking clients, the control hub (SignalR's JSON protocol over a WebSocket), data stream endpoints, the per-address limits and the self-signed certificate with its handover. tokio, axum and rustls; the app supplies a store, its hubs, stream types and the pairing screen |
| `skakel-client` | Find servers, pair, get tokens, pin the server's certificate, follow the control hub and open data streams, on tokio; the hub is a small SignalR client written for what Skakel's hub uses |
| `skakel-vcam` | Feed the virtual camera, and `skakel-vcam-install` to install its media source |
| `skakel-vcam-source` | The virtual camera's media source: the COM DLL Windows' Frame Server loads |

[docs/parts.md](https://github.com/matumi-software/skakel/blob/main/docs/parts.md) says what each
part holds and which one an app takes.

The crates are not on crates.io. An app takes them from this repository, pinned to a commit:

```toml
skakel-client = { git = "https://github.com/matumi-software/skakel", rev = "<commit>" }
```

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
- **Pairing:** a six-digit code that a person compares on both machines, so no secret is ever
  typed or copied.
- **Signing in:** OAuth 2.0 client credentials. The client pins the server's certificate.
- **Control:** gRPC over HTTP/2 on the same port. Skakel's control service carries the certificate
  handover and closing; an app adds gRPC services of its own beside it for its commands and the
  state it pushes, signed in with the same token.
- **Data:** a gRPC stream for each USB device, serial port or app's own stream type, each on a
  connection of its own, with data and control messages in order.

## License

MIT, see [LICENSE](https://github.com/matumi-software/skakel/blob/main/LICENSE). Copyright (c) 2026 Matumi Software.

Contributions are accepted under the same licence. Skakel takes no GPL code, so apps of any licence
can use it.
