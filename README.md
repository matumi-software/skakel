# Skakel

Skakel is the transport between apps on a local network. It covers how a client finds a server,
pairs with it, signs in, follows its state and moves data to and from it. Apps put their own
features on top.

[Koppel](https://github.com/matumi-software/koppel), which shares USB devices and serial ports over
the network, is the first app built on it.

*Skakel* is Afrikaans for a link in a chain, and to connect.

## Status

Version 0.1.0. Protocol version 1 is settled in [docs/protocol.md](https://github.com/matumi-software/skakel/blob/main/docs/protocol.md), and the
client and server libraries are tested against each other. Koppel 0.1.1 is the first app built on them.

## What it holds

| Package | What |
|---|---|
| `Skakel.Protocol` | What clients and servers share: wire constants, discovery packets, the pairing code, the JSON contract and the serial stream's messages |
| `Skakel.Client` | Find servers, pair, get tokens, pin the server's certificate, follow the control hub, open data streams |
| `Skakel.Server` | Issue tokens, approve pairing, revoke clients, host the control hub and the data stream endpoints |
| `Skakel.VirtualCamera` | A Windows 11 virtual camera any app can feed: create or remove it, push frames, set the frame it shows while the app is closed |

The first three are .NET 10 libraries on NuGet.org:

```sh
dotnet add package Skakel.Client
```

A Rust implementation with the same feature set is being written in `src/rust/`, one crate per
part:

| Crate | What |
|---|---|
| `skakel-protocol` | The protocol version, so far |
| `skakel-vcam` | Feed the virtual camera from Rust, the same API as `Skakel.VirtualCamera`, and `skakel-vcam-install` to install its media source |
| `skakel-vcam-source` | The virtual camera's media source: the COM DLL Windows' Frame Server loads |

## Virtual camera

A camera that Teams, Zoom, browsers and the Camera app list by name, fed with frames by an app, on
Windows 11 (`MFCreateVirtualCamera`, no driver). The media source is installed once per machine,
elevated; after that an app creates its camera and feeds it without elevation, from Rust or .NET:

```csharp
using var camera = SkakelVirtualCamera.Create(new SkakelVirtualCameraOptions("Tweeling", 1280, 720, 30));
camera.SetIdleFrame(closedPicture, FramePixelFormat.Bgra);
camera.PushFrame(frame, FramePixelFormat.Bgra);
```

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
- **Control:** REST for commands, SignalR for state the server pushes.
- **Data:** a binary WebSocket for each stream.

## Notes for apps

- Keep the `OpenIddict` log categories at `Warning`. At `Information` and below, OpenIddict logs
  every token request it reads, in full.
- `AddSkakelServer` puts a small middleware at the start of the app's pipeline. It applies the
  per-address limits to the token and pairing paths and caps their bodies at 4 KiB, before routing,
  authentication or the app's own middleware run.

## License

MIT, see [LICENSE](https://github.com/matumi-software/skakel/blob/main/LICENSE). Copyright (c) 2026 Matumi Software.

Contributions are accepted under the same licence. Skakel takes no GPL code, so apps of any licence
can use it.
