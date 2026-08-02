/// Removes terminal control sequences and non-printing control characters from
/// untrusted manager metadata. Newlines and tabs become spaces so one record
/// cannot redraw or visually forge surrounding terminal output.
pub fn terminal_text(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            consume_escape(&mut chars);
            continue;
        }
        if ch.is_control() || is_bidi_control(ch) {
            if matches!(ch, '\n' | '\r' | '\t') && !result.ends_with(' ') {
                result.push(' ');
            }
            continue;
        }
        result.push(ch);
    }
    result.trim().to_string()
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn consume_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek().copied() {
        Some('[') => {
            chars.next();
            for ch in chars.by_ref() {
                if ('@'..='~').contains(&ch) {
                    break;
                }
            }
        }
        Some(']') => {
            chars.next();
            let mut previous_escape = false;
            for ch in chars.by_ref() {
                if ch == '\u{7}' || (previous_escape && ch == '\\') {
                    break;
                }
                previous_escape = ch == '\u{1b}';
            }
        }
        Some(_) => {
            chars.next();
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_terminal_control_sequences() {
        assert_eq!(terminal_text("safe\x1b[2J\x1b[31mred\x1b[0m"), "safered");
        assert_eq!(terminal_text("one\n\ttwo\0"), "one two");
        assert_eq!(terminal_text("x\x1b]0;forged\x07y"), "xy");
        assert_eq!(terminal_text("safe\u{202e}txt"), "safetxt");
    }
}
