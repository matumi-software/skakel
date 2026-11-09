//! Feeds the virtual camera "Skakel Test Pattern" with moving colour bars until Enter is pressed,
//! then leaves it showing its idle frame.
//!
//! ```text
//! cargo run --release -p skakel-vcam --example test_pattern            # feed it
//! cargo run --release -p skakel-vcam --example test_pattern -- --remove # remove the camera
//! ```
//!
//! The media source must be installed first: see `docs/virtual-camera.md`.

#[cfg(windows)]
fn main() -> skakel_vcam::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use skakel_vcam::{CameraOptions, Error, PixelFormat, VirtualCamera, remove_camera};

    const NAME: &str = "Skakel Test Pattern";
    const WIDTH: u32 = 1280;
    const HEIGHT: u32 = 720;
    const FPS: u32 = 30;

    if std::env::args().any(|a| a == "--remove") {
        remove_camera(NAME)?;
        println!("Removed \"{NAME}\".");
        return Ok(());
    }

    let mut camera = match VirtualCamera::create(CameraOptions::new(NAME, WIDTH, HEIGHT, FPS)) {
        Err(Error::Unsupported(why)) => {
            println!("The virtual camera is not supported here: {why}");
            return Ok(());
        }
        other => other?,
    };
    camera.set_idle_frame(&closed_frame(WIDTH, HEIGHT), PixelFormat::Bgra)?;
    println!(
        "Camera \"{NAME}\" ({}), {WIDTH}x{HEIGHT} at {FPS} fps. Open it in an app; press Enter to stop.",
        camera.id()
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = stop.clone();
    std::thread::spawn(move || {
        let _ = std::io::stdin().read_line(&mut String::new());
        stop_reader.store(true, Ordering::Relaxed);
    });

    let mut frame = vec![0u8; (WIDTH * HEIGHT * 4) as usize];
    let start = Instant::now();
    let mut connected = false;
    for n in 0u64.. {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        draw_pattern(&mut frame, WIDTH, HEIGHT, n);
        let delivered = camera.push_frame(&frame, PixelFormat::Bgra)?;
        if delivered != connected {
            connected = delivered;
            println!(
                "{}",
                if connected {
                    "An app has the camera open."
                } else {
                    "Waiting for an app to open the camera."
                }
            );
        }
        let due = start + Duration::from_secs(n + 1) / FPS;
        std::thread::sleep(due.saturating_duration_since(Instant::now()));
    }
    println!("Stopped; the camera shows its idle frame now. Run with --remove to remove it.");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The virtual camera is Windows only.");
}

/// Colour bars that scroll, a white square that bounces, and a frame counter in binary along the
/// bottom, so a stalled or repeated frame is easy to see.
#[cfg_attr(not(windows), allow(dead_code))]
fn draw_pattern(frame: &mut [u8], width: u32, height: u32, n: u64) {
    const BARS: [[u8; 3]; 7] = [
        [192, 192, 192],
        [0, 192, 192],
        [192, 192, 0],
        [0, 192, 0],
        [192, 0, 192],
        [0, 0, 192],
        [192, 0, 0],
    ];
    let (w, h) = (width as usize, height as usize);
    let shift = (n as usize * 4) % w;
    let side = h / 4;
    let span = w - side;
    let travel = (n as usize * 8) % (2 * span);
    let box_x = if travel < span {
        travel
    } else {
        2 * span - travel
    };
    let box_y = (h - side) / 2;
    let bit_width = w / 32;
    for y in 0..h {
        for x in 0..w {
            let in_box = (box_x..box_x + side).contains(&x) && (box_y..box_y + side).contains(&y);
            let rgb = if in_box {
                [255, 255, 255]
            } else if y >= h - bit_width {
                let bit = 31 - (x / bit_width).min(31);
                if (n >> bit) & 1 == 1 {
                    [255, 255, 255]
                } else {
                    [16, 16, 16]
                }
            } else {
                BARS[((x + shift) % w) * BARS.len() / w]
            };
            let at = (y * w + x) * 4;
            frame[at..at + 4].copy_from_slice(&[rgb[2], rgb[1], rgb[0], 255]);
        }
    }
}

/// Dark grey with CLOSED across the middle, in BGRA.
#[cfg_attr(not(windows), allow(dead_code))]
fn closed_frame(width: u32, height: u32) -> Vec<u8> {
    const GLYPHS: [[u8; 7]; 6] = [
        [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110,
        ], // C
        [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ], // L
        [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ], // O
        [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ], // S
        [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ], // E
        [
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ], // D
    ];
    let (w, h) = (width as usize, height as usize);
    let scale = (w / 60).max(1);
    let text_width = (GLYPHS.len() * 6 - 1) * scale;
    let (left, top) = (
        (w.saturating_sub(text_width)) / 2,
        (h.saturating_sub(7 * scale)) / 2,
    );
    let mut frame = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let lit = x >= left && y >= top && {
                let (cx, cy) = ((x - left) / scale, (y - top) / scale);
                let (glyph, column) = (cx / 6, cx % 6);
                glyph < GLYPHS.len()
                    && column < 5
                    && cy < 7
                    && (GLYPHS[glyph][cy] >> (4 - column)) & 1 == 1
            };
            let v = if lit { 220 } else { 48 };
            frame[(y * w + x) * 4..][..4].copy_from_slice(&[v, v, v, 255]);
        }
    }
    frame
}
