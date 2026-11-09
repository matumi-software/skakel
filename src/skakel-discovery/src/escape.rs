//! Writing the answer's JSON with the escaping discovery has used since protocol version 1, so
//! every side cuts a name at the same place when an answer has to fit in a probe.
//!
//! The escaping is the relaxed one of .NET's `System.Text.Json` (`UnsafeRelaxedJsonEscaping`),
//! where the format came from: text outside ASCII goes out as UTF-8, except what that encoder does
//! not call a defined, printable character of the Basic Multilingual Plane (everything above
//! U+FFFF, private use, unassigned code points, spaces other than U+0020), which becomes `\uXXXX`
//! with uppercase hex, one escape per UTF-16 code unit. `serde_json` already escapes `"`, `\` and
//! control characters; this adds the rest.

use std::io;

use serde::Serialize;
use unicode_general_category::{GeneralCategory, get_general_category};

struct Relaxed;

impl serde_json::ser::Formatter for Relaxed {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (index, c) in fragment.char_indices() {
            if !is_written_as_is(c) {
                writer.write_all(&fragment.as_bytes()[start..index])?;
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04X}")?;
                }
                start = index + c.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

fn is_written_as_is(c: char) -> bool {
    if c.is_ascii() {
        return true;
    }
    if u32::from(c) > 0xFFFF {
        return false;
    }
    !matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::SpaceSeparator
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::Surrogate
    )
}

/// The JSON bytes of `value`, escaped as `UnsafeRelaxedJsonEscaping` does.
pub(crate) fn to_vec<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, Relaxed);
    value
        .serialize(&mut serializer)
        .expect("a discovery answer is always valid JSON");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> String {
        String::from_utf8(to_vec(&text)).unwrap()
    }

    #[test]
    fn to_vec_writes_text_outside_ascii_as_utf8() {
        assert_eq!(json("caf\u{E9} \u{4E2D}"), "\"caf\u{E9} \u{4E2D}\"");
    }

    #[test]
    fn to_vec_escapes_what_the_relaxed_escaping_escapes() {
        assert_eq!(json("\u{1F600}"), "\"\\uD83D\\uDE00\"");
        assert_eq!(json("a\u{00A0}b"), "\"a\\u00A0b\"");
        assert_eq!(json("\u{E000}"), "\"\\uE000\"");
        assert_eq!(json("\"\\"), r#""\"\\""#);
    }

    #[test]
    fn to_vec_leaves_the_characters_the_relaxed_escaping_leaves() {
        assert_eq!(json("'<>&+"), "\"'<>&+\"");
    }
}
