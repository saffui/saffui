/// A message the POST binding carried in a form field: base64, with the line
/// breaks some senders put in it; nothing when it is not base64 or not UTF-8. The
/// message limits apply when it is read.
pub fn decode_posted_message(value: &str) -> Option<String> {
    let compact: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let decoded = data_encoding::BASE64.decode(&compact).ok()?;
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::decode_posted_message;

    /// A posted message decodes with or without line breaks, and what is not
    /// base64 or not UTF-8 does not.
    #[test]
    fn a_posted_message_decodes_across_line_breaks() {
        let message = "<samlp:LogoutResponse/>";
        let encoded = data_encoding::BASE64.encode(message.as_bytes());
        let broken = format!("{}\r\n{}\n", &encoded[..8], &encoded[8..]);
        for value in [encoded.as_str(), broken.as_str()] {
            assert_eq!(decode_posted_message(value).as_deref(), Some(message));
        }
        assert_eq!(decode_posted_message("not base64!"), None);
        assert_eq!(
            decode_posted_message(&data_encoding::BASE64.encode(&[0xff, 0xfe])),
            None
        );
    }
}
