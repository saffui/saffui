//! Base58 in the Bitcoin alphabet, as `did:key`, `did:web` documents and
//! multibase's `z` write keys.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The bytes read as one big-endian number, written in base 58, each leading
/// zero byte kept as a leading `1`.
pub fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    // Least significant digit first while the number is built.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| char::from(ALPHABET[usize::from(*digit)])),
        )
        .collect()
}

/// The bytes a base58 text writes, or `None` for a character outside the
/// alphabet.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text
        .bytes()
        .take_while(|character| *character == b'1')
        .count();
    // Least significant byte first while the number is built.
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len() * 733 / 1000 + 1);
    for character in text.bytes() {
        let mut carry = u32::try_from(ALPHABET.iter().position(|held| *held == character)?).ok()?;
        for byte in &mut bytes {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut decoded = vec![0_u8; zeros];
    decoded.extend(bytes.iter().rev());
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_reads_back_as_the_bytes_it_writes() {
        for bytes in [
            &[][..],
            &[0, 0, 1],
            &[0xed, 0x01, 0xff, 0x00, 0x7f],
            &[0; 3],
        ] {
            assert_eq!(decode(&encode(bytes)).as_deref(), Some(bytes));
        }
        assert_eq!(encode(&[0, 0, 1]), "112");
        assert_eq!(decode("0OIl"), None, "outside the alphabet");
    }
}
