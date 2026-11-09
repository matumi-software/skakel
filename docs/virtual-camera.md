# Skakel virtual camera

Layout version 1. This is the contract between the apps that feed the camera (producers) and the
media source that Windows runs it on. The producer, `skakel-vcam`, and the media source,
`skakel-vcam-source`, follow it, and so must any other producer. A change to anything below changes
this file in the same pull request.

Windows 11 only (build 22000 or later): the camera is made with `MFCreateVirtualCamera`, which
Windows 10 does not have. There, the producer reports the camera as unsupported
(`Error::Unsupported`) instead of failing.

## The parts

- **The media source** is a COM DLL, `skakel_vcam_source-<version>.dll`, installed once per machine
  in `%ProgramFiles%\Skakel\VirtualCamera` and registered under HKLM. Windows' Frame Server service
  loads it whenever an app opens a Skakel camera. It reads frames from shared memory and hands them
  to Frame Server at the camera's rate.
- **A producer** is the app. It creates the camera for its user (no elevation needed), then writes
  frames into the shared memory. It never talks to the media source in any other way.
- **A camera** is what Teams, Zoom, browsers and the Camera app list. Windows adds "Windows Virtual
  Camera" to its name in some places. It belongs to one user and stays, across restarts, until the
  producer removes it.

```
app (producer) --writes--> Global\Skakel.VirtualCamera.<id> --reads--> media source (in Frame Server) --> Teams, Camera app, ...
```

## Creating and removing a camera

The producer calls `MFCreateVirtualCamera` with:

| Parameter | Value |
|---|---|
| type | `MFVirtualCameraType_SoftwareCameraSource` |
| lifetime | `MFVirtualCameraLifetime_System`: the camera outlives the app, so it can show the idle frame |
| access | `MFVirtualCameraAccess_CurrentUser`: no elevation needed, and each user gets their own camera |
| friendlyName | the camera's name, 1 to 128 characters |
| sourceId | `{8138410C-B0A8-4CBC-9E0E-5920362ED550}`, the media source's CLSID |

Windows keys the camera off these parameters, so calling it again with the same name opens the same
camera. Creating is: open, set the attributes below, `Start`. Removing is: open, `Remove`.

The producer sets these attributes on the `IMFVirtualCamera` before `Start`. Frame Server copies them
into the media source's activation object.

| Attribute | GUID | Type | Value |
|---|---|---|---|
| Camera id | `2823b277-8caa-4866-b746-68f84ca14f41` | string | see "The camera id" |
| Width | `cf28fa9f-2299-4faa-8cb9-a39776b685de` | UINT32 | even, 16 to 4096 |
| Height | `b32ef9c4-4e8f-4d60-8df9-d6e8ecee1900` | UINT32 | even, 16 to 4096 |
| Frame rate | `6818edaf-afd8-4a30-8852-945669ae9cb0` | UINT64 | numerator in the high 32 bits, denominator in the low, as `MF_MT_FRAME_RATE`; 1 to 120 a second |
| Producer SID | `0a7bd1e8-c693-4bff-8f51-4d15b4b7606a` | string | the producer's user, `S-1-5-...` |
| Layout version | `52a2c5ab-38fe-4d3e-aa11-8045bb97aaf7` | UINT32 | `1` |

Without a usable size and rate the media source runs at 1280x720, 30 fps. Without a usable camera
id, or with another layout version, it opens no shared memory and shows only its built-in idle
frame.

Changing an existing camera's size or rate: remove it and create it again. Whether Windows applies
new attributes to a camera that exists already is not established, and the shared memory, once made,
keeps its size. A producer that finds the memory at another size reports it (`CameraMismatch`,
`InvalidOperationException`).

### The camera id

16 lowercase hex digits: FNV-1a 64 over the UTF-8 of `<producer SID>\n<friendly name>`. FNV-1a 64
starts at `0xcbf29ce484222325` and, for each byte, XORs it in and multiplies by `0x100000001b3`.
The SID keeps two users' cameras of the same name apart. The media source accepts only an id of
exactly this shape, since it builds a kernel object name and a file name from it.

For SID `S-1-5-21-1004336348-1177238915-682003330-512` and name `Tweeling` the id is
`313c3868b45ee1ae`; both sides pin this in a test.

## The shared memory

A section object (pagefile-backed shared memory) named `Global\Skakel.VirtualCamera.<id>`.

**The media source creates it**, when an app starts streaming from the camera. A `Global\` object
needs `SeCreateGlobalPrivilege`, which the Frame Server's service accounts have and a user's app does
not; it also means nobody but a service or an administrator can create it first. Its DACL:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GRGW;;;<producer SID>)
```

System, administrators and Local Service (the Frame Server's account) get full access; the producer's
user gets read and write. Without a valid producer SID attribute, `IU` (interactive users) takes its
place.

**The producer opens it** with read and write access. Until an app opens the camera it does not
exist, and the producer drops frames (`push_frame` returns false) and looks for it again
at most every 250 ms. Once the producer holds it open, it stays alive even when the media source lets
go, and the next media source opens the same one; the producer never needs to reconnect.

A media source that finds the section existing opens it read-only and checks the header. If its
format differs from the camera's, the source shows its idle frame and leaves the memory alone.

### Layout

All values little-endian. Total size: `4096 + 4 * slot_size`.

| Offset | Size | Field | Written by |
|---|---|---|---|
| 0 | 4 | magic, `SKVC` (`0x43564B53`) | source, last, with release |
| 4 | 4 | layout version, `1` | source |
| 8 | 4 | header size, `4096` | source |
| 12 | 4 | width | source |
| 16 | 4 | height | source |
| 20 | 4 | frame rate numerator | source |
| 24 | 4 | frame rate denominator | source |
| 28 | 4 | pixel format, `NV12` (`0x3231564E`) | source |
| 32 | 4 | frame size, `width * height * 3 / 2` | source |
| 36 | 4 | slot count, `3` | source |
| 40 | 4 | slot size, the frame size rounded up to a multiple of 64 | source |
| 44 | 4 | reserved, 0 | |
| 48 | 8 | total size | source |
| 56 | 8 | reserved, 0 | |
| 64 | 4 | producer state: 1 attached, 0 gone | producer |
| 68 | 4 | producer process id, for diagnostics | producer |
| 72 | 4 | idle timeout in ms, 0 for the default 2000; clamped to 100 to 60000 | producer |
| 76 | 4 | reserved, 0 | |
| 80 | 8 | frame sequence: the latest complete frame's number, 0 for none | producer |
| 88 | 8 | idle sequence: the idle frame's version, 0 for none | producer |
| 96 | 8 x 3 | slot sequences: the frame number each slot holds | producer |
| 4096 | slot size x 3 | frame slots 0, 1, 2 | producer |
| 4096 + 3 x slot size | slot size | the idle slot | producer |

The media source writes the fixed fields once, on memory it has just created, which is all zeros;
the magic goes last with release semantics, so a reader that sees it sees the whole header. A reader
that finds the magic still 0 tries again shortly.

### Frames

Every frame is NV12 at the camera's size, tightly packed: `width * height` bytes of luma (Y), then
`width * height / 2` bytes of interleaved chroma (U, V) at half width and half height. BT.601,
limited range (Y 16 to 235), which is what webcams send and what apps assume when they are not told.
The media type says so (`MF_MT_YUV_MATRIX` BT.601, `MF_MT_VIDEO_NOMINAL_RANGE` 16-235).

The producers convert RGBA and BGRA for the app, with this integer arithmetic so both give the same
bytes (`>>` is an arithmetic shift):

```
Y = ((66 R + 129 G + 25 B + 128) >> 8) + 16
U = ((-38 R - 74 G + 112 B + 128) >> 8) + 128
V = ((112 R - 94 G - 18 B + 128) >> 8) + 128
```

Each U and V comes from the average of the 2x2 block it covers: `(sum + 2) >> 2` per channel, then
the formula. Alpha is ignored.

### The ring and its sequence numbers

The producer never waits and the media source never blocks the producer. Each slot is guarded by its
sequence number, a sequence lock:

**Writing frame `k`** (`k` = frame sequence + 1), into slot `k % 3`:

1. Store `0xFFFFFFFFFFFFFFFF` (writing) in the slot's sequence, then a release fence.
2. Write the frame into the slot.
3. Store `k` in the slot's sequence, with release.
4. Store `k` in the frame sequence, with release.

**Reading** the newest frame:

1. Load the frame sequence `k`, with acquire. If it is 0, or the frame this reader had last, there is
   nothing new.
2. Load slot `k % 3`'s sequence, with acquire. If it is not `k`, the producer has moved on: skip.
3. Copy the slot into a private buffer, then an acquire fence.
4. Load the slot's sequence again. If it is still `k`, the copy is whole; otherwise drop it.

The producer can lap a slow reader by three frames before a slot the reader is copying is
overwritten, and when that happens the reader notices and keeps its previous frame. A media source
opening the memory takes the current frame sequence as already seen, so it never shows a frame left
behind by a producer that has since gone.

A new producer attaching to memory that another producer used counts on from the frame sequence it
finds. Only one producer should write a camera at a time; two would interleave their frames.

**The idle frame** works the same way with the idle sequence and the idle slot: store writing, fence,
write, store the next version (1, 2, ...). A producer that finds the idle sequence at writing (a
producer that died mid-write) counts on from 0.

**Attaching** is: write the idle timeout and process id, then store 1 in the producer state with
release; then, if the app set an idle frame, write it. **Detaching** (the producer is disposed or
dropped) stores 0 in the producer state.

## Pacing and the idle frame

Frame Server asks for frames with `RequestSample`. The media source does not answer at once: a thread
wakes once per frame on a fixed grid, `t(n) = t0 + n * 10^7 * den / num` in 100 ns units on the clock
of `MFGetSystemTime`, and on each tick answers the oldest waiting request. The sample's time is
`t(n)` and its duration `t(n+1) - t(n)`. When the thread wakes late it sends the slot it is in and
skips the ones it missed, so sample times always step by whole frames and never bunch up. When every
sample is still downstream, the tick is skipped and the request waits for the next.

Each tick the source takes in whatever the producer wrote, whether or not a request is waiting, and
picks the picture:

- **the producer's latest frame**, new or repeated, while the producer state is 1 and its latest
  frame is no older than the idle timeout;
- **the idle frame** otherwise: right away when the producer detached, after the timeout when it
  stopped writing or died.

The idle frame is the producer's (from the idle slot) when it set one, else the one in its idle file,
else a built-in near-black frame. When the producer writes again, its frames return on the next tick.

Microsoft's sample and VCamSample answer each request at once and stamp it with the time of the
request. VCamSample reports Teams showing its own preview but sending nothing to the other side of a
call; steady, whole-frame sample times are the first thing to rule out there.

### The idle file

So the camera can say "<App> is closed" after the app has gone, the producer also writes its idle
frame to `%ProgramData%\Skakel\VirtualCamera\<id>.idle` (written beside it and renamed over):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic, `SKVI` (`0x49564B53`) |
| 4 | 4 | version, `1` |
| 8 | 4 | width |
| 12 | 4 | height |
| 16 | frame size | the NV12 frame |

The media source reads it when a stream starts, and uses it only when its size is exactly right.

## Sizes and rates

- Width and height: even, 16 to 4096. Rate: 1 to 120 frames a second; the producers take whole
  numbers, the layout carries a fraction.
- One stream, one media type: NV12 at the camera's size and rate. Frame Server converts for apps that
  want another format.
- Memory: 1280x720 is 1,382,400 bytes a frame and 5.5 MB in all; 1920x1080 is 3,110,400 bytes and
  12.4 MB; 3840x2160 is 49.8 MB.

## Installing and upgrading

Both need an elevated process. `skakel-vcam-install` does it:

```
skakel-vcam-install install <path to skakel_vcam_source.dll>
skakel-vcam-install uninstall
skakel-vcam-install status
```

**Install** reads the DLL's version from its export `SkakelVirtualCameraVersion`, copies it to
`%ProgramFiles%\Skakel\VirtualCamera\skakel_vcam_source-<version>.dll`, and registers:

```
HKLM\Software\Classes\CLSID\{8138410C-B0A8-4CBC-9E0E-5920362ED550}
    (default) = Skakel virtual camera source
HKLM\Software\Classes\CLSID\{8138410C-B0A8-4CBC-9E0E-5920362ED550}\InprocServer32
    (default) = <path of the versioned DLL>
    ThreadingModel = Both
```

It must be HKLM, not HKCU: Frame Server runs as a service. It must be a folder the service accounts
can read, such as Program Files, not a user's profile. The DLL also exports `DllRegisterServer` and
`DllUnregisterServer`, so `regsvr32` registers it where it stands; an installer of its own (MSI,
WiX) may write the keys above instead.

**Upgrades** work while a camera made with the old version is in use. Frame Server keeps the DLL
loaded as long as the camera's source lives, so the file cannot be replaced in place: each version
has its own file name, the CLSID stays the same and is pointed at the new file, and the old file is
deleted, or marked for deletion at the next restart when it is still loaded. Cameras keep working,
because they refer to the CLSID, not the file; each picks up the new version the next time it
starts. A newer source must keep reading layout version 1, or the version goes up here and both
producers with it.

**Uninstall** removes the CLSID and the files. Cameras users created stay listed until each user's
app removes its own (`remove`, `Remove`); without the source they no longer start.

Several apps may ship the media source. They share one CLSID and one folder, so the last install
wins; an app's uninstaller should leave the source in place while another app still uses it.

## Signing

Smart App Control and some enterprise policies block unsigned DLLs, and Frame Server loads this one
into a service. The release build leaves room for signing: sign the DLL (and the installer) after
`cargo build --release` and before installing, for example

```
signtool sign /fd SHA256 /tr <timestamp URL> /td SHA256 /f <certificate> target\release\skakel_vcam_source.dll
```

The installer copies the file as it is, so the signature carries over to the versioned copy. The
DLL links the C runtime statically (`src/.cargo/config.toml`), so it needs no Visual C++
redistributable on the machine.

## Debugging

The media source writes what it does to the debugger output, prefixed `[skakel-vcam <pid>]`;
DebugView, run as administrator with "Capture Global Win32" on, shows it from the Frame Server's
processes. Microsoft's sample's `Debug-FrameServer.ps1` shows how to attach a debugger to them.

## Known risks

- **Teams**: VCamSample reports Teams sending nothing to the other side of a call. The pacing above
  is meant to fix that; if it does not, the fallback is a DirectShow source in the pattern of softcam
  (MIT) for those apps.
- **Chrome and Meet**: one report of "camera busy" until Chrome's Media Foundation capture was turned
  off.

## Credits

The media source's COM objects follow Microsoft's VirtualCamera sample (microsoft/Windows-Camera,
Samples/VirtualCamera, MIT, Copyright (c) Microsoft Corporation) and VCamSample (smourier/VCamSample,
MIT, Copyright (c) 2024-2026 Simon Mourier). No code from GPL or AGPL projects is used.
