//! What the command line writes on a terminal. A string that came from a
//! node is written with every character that is not shown as itself escaped:
//! a name carrying an escape sequence or a change of direction must not move
//! the cursor, change the title of the window, or show other than it holds.

use std::fmt::Write as _;

/// `text`, with each control, format or separator character, and the
/// backslash, written as `\u{…}`: two different texts are never written alike.
pub(crate) fn neutralize(text: &str) -> String {
    let mut written = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '\\' || character.is_control() || is_format_or_separator(character) {
            let _ = write!(written, "\\u{{{:x}}}", u32::from(character));
        } else {
            written.push(character);
        }
    }
    written
}

/// The format characters of Unicode 16 and 17, which agree on them (category
/// Cf: marks and overrides of direction, invisible joiners, tags), and the
/// line and paragraph separators.
fn is_format_or_separator(character: char) -> bool {
    matches!(
        character,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

#[cfg(test)]
mod tests {
    use super::neutralize;

    #[test]
    fn a_control_character_is_written_escaped_and_the_rest_as_it_is() {
        assert_eq!(neutralize("acme"), "acme");
        assert_eq!(neutralize("ac\u{1b}[2Jme"), "ac\\u{1b}[2Jme");
        assert_eq!(neutralize("a\nb\u{9b}c"), "a\\u{a}b\\u{9b}c");
        assert_eq!(neutralize("éclair ✓"), "éclair ✓");
    }

    #[test]
    fn a_change_of_direction_an_invisible_character_and_a_backslash_are_written_escaped() {
        assert_eq!(neutralize("abc\u{202e}fed"), "abc\\u{202e}fed");
        assert_eq!(neutralize("ac\u{200b}me"), "ac\\u{200b}me");
        assert_eq!(neutralize("a\u{2028}b"), "a\\u{2028}b");
        assert_eq!(neutralize("\\u{1b}"), "\\u{5c}u{1b}");
        assert_ne!(neutralize("\\u{1b}"), neutralize("\u{1b}"));
    }
}
