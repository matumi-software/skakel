//! The cleaning a client applies to a server's name and app version.

use unicode_general_category::{GeneralCategory, get_general_category};

/// Text a person can be shown: without control characters, format characters (such as bidi
/// overrides and zero-width ones) or line and paragraph separators (Unicode categories Cc, Cf, Zl
/// and Zp), trimmed and cut to `max_length` Unicode scalar values, never through one. What a client
/// applies to a server's name and app version, from discovery and from info alike.
///
/// Lengths are in Unicode scalar values (what Rust's `char` is), not bytes and not UTF-16 code
/// units, so an emoji counts for one. A combining mark counts for one too: what a person sees as
/// one character may be several.
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

    let mut clean: String = kept.trim().chars().take(max_length).collect();
    // A cut inside the text can leave the space before it at the end.
    clean.truncate(clean.trim_end().len());
    clean
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
    fn clean_cuts_to_length_in_scalar_values_and_never_through_one() {
        assert_eq!(clean(&"n".repeat(100), 63).len(), 63);
        // An emoji is one scalar value, so 63 of them fit, and so do 62 letters and one emoji.
        assert_eq!(clean(&"\u{1F600}".repeat(100), 63).chars().count(), 63);
        assert_eq!(
            clean(&format!("{}\u{1F600}", "n".repeat(62)), 63),
            format!("{}\u{1F600}", "n".repeat(62))
        );
        assert_eq!(
            clean(&format!("{}\u{1F600}", "n".repeat(63)), 63),
            "n".repeat(63)
        );
        assert_eq!(clean("", 63), "");
        assert_eq!(clean("abc", 0), "");
    }

    #[test]
    fn clean_leaves_no_space_at_the_end_after_a_cut() {
        assert_eq!(clean("abc   def", 5), "abc");
        assert_eq!(clean("abc   def", 6), "abc");
        assert_eq!(clean("abc d", 4), "abc");
        assert_eq!(clean("abc   def", 7), "abc   d");
        assert_eq!(clean("abc\u{3000}\u{3000}def", 4), "abc");
    }

    #[test]
    fn clean_trims_after_it_drops() {
        assert_eq!(clean("\u{200B} a b \u{200B}", 63), "a b");
        assert_eq!(clean("\u{3000}\u{00A0}x", 63), "x");
    }
}
