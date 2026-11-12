//! How a client's name is kept.

use unicode_general_category::{GeneralCategory, get_general_category};

/// A client's name as the server keeps it: control and format characters (categories Cc and Cf)
/// taken out, then trimmed.
pub fn clean_client_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| {
            !matches!(
                get_general_category(*c),
                GeneralCategory::Control | GeneralCategory::Format
            )
        })
        .collect();
    kept.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_names_lose_control_and_format_characters_and_the_spaces_around() {
        assert_eq!(clean_client_name("  lab\u{0}\u{202E} pc \n"), "lab pc");
        assert_eq!(clean_client_name("\u{200B}\u{0}"), "");
        assert_eq!(clean_client_name("Zo\u{eb}"), "Zo\u{eb}");
    }
}
