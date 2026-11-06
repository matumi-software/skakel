//! The cleaning a client applies to a server's name and app version.

use unicode_general_category::{GeneralCategory, get_general_category};

/// Text a person can be shown: without control characters, format characters (such as bidi
/// overrides and zero-width ones) or line and paragraph separators (Unicode categories Cc, Cf, Zl
/// and Zp), trimmed and cut to `max_length` UTF-16 code units, never through a surrogate pair.
/// What a client applies to a server's name and app version, from discovery and from info alike.
///
/// Lengths are in UTF-16 code units, not bytes or characters, because that is what the .NET side
/// counts and both must keep the same text.
pub fn clean(text: &str, max_length: usize) -> String {
    let kept: String = text
        .chars()
        .filter(|c| {
            !matches!(
                get_general_category(*c),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            )
        })
        .collect();

    let mut clean = String::new();
    let mut units = 0;
    for c in kept.trim().chars() {
        units += c.len_utf16();
        if units > max_length {
            break;
        }
        clean.push(c);
    }
    clean
}

/// The length of `text` in UTF-16 code units, which is what .NET calls its length.
pub(crate) fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_drops_control_and_format_characters() {
        let cases = [
            ("pi\u{202E}lab", "pilab"),
            ("pi\u{200B}lab\u{200D}", "pilab"),
            ("pi\u{2066}lab\u{2069}", "pilab"),
            (" pi\nlab\u{2028} ", "pilab"),
            ("pi\u{E0041}lab", "pilab"),
            ("pi-lab \u{1F600}", "pi-lab \u{1F600}"),
        ];

        for (text, expected) in cases {
            assert_eq!(clean(text, 63), expected, "{text:?}");
        }
    }

    #[test]
    fn clean_cuts_to_length_without_splitting_a_surrogate_pair() {
        assert_eq!(clean(&"n".repeat(100), 63).len(), 63);
        assert_eq!(
            clean(&format!("{}\u{1F600}", "n".repeat(62)), 63),
            "n".repeat(62)
        );
        assert_eq!(
            clean(&format!("{}\u{1F600}", "n".repeat(61)), 63),
            format!("{}\u{1F600}", "n".repeat(61))
        );
        assert_eq!(clean("", 63), "");
        assert_eq!(clean("abc", 0), "");
    }

    #[test]
    fn clean_trims_after_it_drops() {
        assert_eq!(clean("\u{200B} a b \u{200B}", 63), "a b");
        assert_eq!(clean("\u{3000}\u{00A0}x", 63), "x");
    }
}
