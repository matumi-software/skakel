//! RGBA and BGRA to NV12, BT.601 limited range, the way webcams deliver it.
//!
//! Fixed-point integer arithmetic, so the .NET producer computes the same bytes; the tests pin a
//! few of them and the .NET tests pin the same ones.

use std::fmt;

/// The pixel layout of a frame handed to the producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// NV12: the luma plane, then interleaved U and V at half width and half height.
    Nv12,
    /// Four bytes a pixel: red, green, blue, then alpha, which is ignored.
    Rgba,
    /// Four bytes a pixel: blue, green, red, then alpha, which is ignored. Windows' usual layout.
    Bgra,
}

impl PixelFormat {
    /// Bytes in a tightly packed frame of this format.
    pub fn frame_size(self, width: u32, height: u32) -> usize {
        let pixels = width as usize * height as usize;
        match self {
            Self::Nv12 => pixels * 3 / 2,
            Self::Rgba | Self::Bgra => pixels * 4,
        }
    }
}

/// A frame of the wrong size for its format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeMismatch {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for SizeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the frame is {} bytes, the camera's size needs {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for SizeMismatch {}

/// Writes `src`, a tightly packed frame in `format`, into `dst` as NV12. Width and height are even.
pub fn to_nv12(
    src: &[u8],
    format: PixelFormat,
    width: u32,
    height: u32,
    dst: &mut [u8],
) -> Result<(), SizeMismatch> {
    let expected = format.frame_size(width, height);
    if src.len() != expected {
        return Err(SizeMismatch {
            expected,
            actual: src.len(),
        });
    }
    let nv12 = PixelFormat::Nv12.frame_size(width, height);
    if dst.len() != nv12 {
        return Err(SizeMismatch {
            expected: nv12,
            actual: dst.len(),
        });
    }
    match format {
        PixelFormat::Nv12 => dst.copy_from_slice(src),
        PixelFormat::Rgba => rgb32_to_nv12::<0, 1, 2>(src, width as usize, height as usize, dst),
        PixelFormat::Bgra => rgb32_to_nv12::<2, 1, 0>(src, width as usize, height as usize, dst),
    }
    Ok(())
}

/// Luma of one pixel, 16 to 235.
pub fn luma(r: i32, g: i32, b: i32) -> u8 {
    (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8
}

/// Blue-difference chroma, 16 to 240.
pub fn chroma_u(r: i32, g: i32, b: i32) -> u8 {
    (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8
}

/// Red-difference chroma, 16 to 240.
pub fn chroma_v(r: i32, g: i32, b: i32) -> u8 {
    (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8
}

fn rgb32_to_nv12<const R: usize, const G: usize, const B: usize>(
    src: &[u8],
    width: usize,
    height: usize,
    dst: &mut [u8],
) {
    let (y_plane, uv_plane) = dst.split_at_mut(width * height);
    let stride = width * 4;
    for (row, y_row) in y_plane.chunks_exact_mut(width).enumerate() {
        let src_row = &src[row * stride..][..stride];
        for (y, px) in y_row.iter_mut().zip(src_row.as_chunks::<4>().0) {
            *y = luma(px[R].into(), px[G].into(), px[B].into());
        }
    }
    // Each chroma sample is taken from the average of its 2x2 block.
    for (pair, uv_row) in uv_plane.chunks_exact_mut(width).enumerate() {
        let top = &src[pair * 2 * stride..][..stride];
        let bottom = &src[(pair * 2 + 1) * stride..][..stride];
        for (x, uv) in uv_row.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let at = x * 8;
            let sum = |c: usize| {
                i32::from(top[at + c])
                    + i32::from(top[at + 4 + c])
                    + i32::from(bottom[at + c])
                    + i32::from(bottom[at + 4 + c])
            };
            let (r, g, b) = ((sum(R) + 2) >> 2, (sum(G) + 2) >> 2, (sum(B) + 2) >> 2);
            uv[0] = chroma_u(r, g, b);
            uv[1] = chroma_v(r, g, b);
        }
    }
}

/// A solid NV12 frame of one colour, given as RGB.
pub fn solid_nv12(width: u32, height: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
    let luma_len = width as usize * height as usize;
    let (r, g, b) = (i32::from(r), i32::from(g), i32::from(b));
    let mut frame = vec![luma(r, g, b); luma_len * 3 / 2];
    for uv in frame[luma_len..].as_chunks_mut::<2>().0 {
        uv[0] = chroma_u(r, g, b);
        uv[1] = chroma_v(r, g, b);
    }
    frame
}

/// FNV-1a, 64 bits. Used for camera ids and to pin test bytes in both languages.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgba(width: u32, height: u32, pixel: impl Fn(u32, u32) -> [u8; 4]) -> Vec<u8> {
        let pixel = &pixel;
        (0..height)
            .flat_map(|y| (0..width).flat_map(move |x| pixel(x, y)))
            .collect::<Vec<_>>()
    }

    #[test]
    fn primaries_land_on_the_bt601_values() {
        let cases: [([i32; 3], (u8, u8, u8)); 5] = [
            ([0, 0, 0], (16, 128, 128)),
            ([255, 255, 255], (235, 128, 128)),
            ([255, 0, 0], (82, 90, 240)),
            ([0, 255, 0], (144, 54, 34)),
            ([0, 0, 255], (41, 240, 110)),
        ];
        for ([r, g, b], (y, u, v)) in cases {
            assert_eq!(
                (luma(r, g, b), chroma_u(r, g, b), chroma_v(r, g, b)),
                (y, u, v),
                "rgb {r} {g} {b}"
            );
        }
    }

    #[test]
    fn rgba_and_bgra_give_the_same_frame() {
        let (w, h) = (16, 16);
        let src = rgba(w, h, |x, y| {
            [(x * 16) as u8, (y * 16) as u8, ((x + y) * 8) as u8, 255]
        });
        let bgra: Vec<u8> = src
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|p| [p[2], p[1], p[0], p[3]])
            .collect();
        let mut a = vec![0; PixelFormat::Nv12.frame_size(w, h)];
        let mut b = a.clone();
        to_nv12(&src, PixelFormat::Rgba, w, h, &mut a).unwrap();
        to_nv12(&bgra, PixelFormat::Bgra, w, h, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn chroma_averages_each_two_by_two_block() {
        // Left block half red, half blue; right block all white.
        let src = rgba(4, 2, |x, y| match (x, y) {
            (0, _) => [255, 0, 0, 255],
            (1, _) => [0, 0, 255, 255],
            _ => [255, 255, 255, 255],
        });
        let mut dst = vec![0; 12];
        to_nv12(&src, PixelFormat::Rgba, 4, 2, &mut dst).unwrap();
        assert_eq!(&dst[..8], &[82, 41, 235, 235, 82, 41, 235, 235]);
        // Average of red and blue is (128, 0, 128).
        assert_eq!(
            &dst[8..],
            &[chroma_u(128, 0, 128), chroma_v(128, 0, 128), 128, 128]
        );
    }

    #[test]
    fn pins_the_bytes_of_a_gradient() {
        // The .NET tests pin the same hash for the same gradient.
        let (w, h) = (16, 16);
        let src = rgba(w, h, |x, y| {
            [(x * 16) as u8, (y * 16) as u8, ((x + y) * 8) as u8, 255]
        });
        let mut dst = vec![0; PixelFormat::Nv12.frame_size(w, h)];
        to_nv12(&src, PixelFormat::Rgba, w, h, &mut dst).unwrap();
        assert_eq!(format!("{:016x}", fnv1a64(&dst)), GRADIENT_NV12_FNV);
    }

    const GRADIENT_NV12_FNV: &str = "26f90e1faa0a07b9";

    #[test]
    fn refuses_a_frame_of_the_wrong_size() {
        let mut dst = vec![0; 384];
        assert_eq!(
            to_nv12(&[0; 10], PixelFormat::Rgba, 16, 16, &mut dst),
            Err(SizeMismatch {
                expected: 1024,
                actual: 10
            })
        );
    }

    #[test]
    fn nv12_is_copied_as_is() {
        let src: Vec<u8> = (0..384).map(|i| i as u8).collect();
        let mut dst = vec![0; 384];
        to_nv12(&src, PixelFormat::Nv12, 16, 16, &mut dst).unwrap();
        assert_eq!(src, dst);
    }

    #[test]
    fn solid_frame_matches_a_converted_one() {
        let src = rgba(16, 16, |_, _| [10, 200, 30, 255]);
        let mut dst = vec![0; 384];
        to_nv12(&src, PixelFormat::Rgba, 16, 16, &mut dst).unwrap();
        assert_eq!(solid_nv12(16, 16, 10, 200, 30), dst);
    }

    #[test]
    fn fnv1a64_matches_the_reference_values() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
